/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2015   Dennis A. Bush, Jr.   bush@tcnj.edu
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Additional permission under GNU GPL version 3 section 7
 *
 *  If you modify this program, or any covered work, by linking or
 *  combining it with the OpenSSL project's OpenSSL library (or a
 *  modified version of that library), containing parts covered by the
 *  terms of the OpenSSL or SSLeay licenses, the copyright holder
 *  grants you additional permission to convey the resulting work.
 *  Corresponding Source for a non-source form of such a combination
 *  shall include the source code for the parts of OpenSSL used as well
 *  as that of the covered work.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <math.h>

#ifdef WINDOWS

#include <io.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Mswsock.h>

#include "uftp.h"
#include "uftp_common.h"
#include "encryption.h"
#include "win_func.h"

void getiflist(struct iflist *list, int *len)
{
    IP_ADAPTER_ADDRESSES *head, *curr;
    IP_ADAPTER_UNICAST_ADDRESS *uni;
    char *buf;
    int buflen, err, i;

    buflen = 100000;
    buf = safe_calloc(buflen, 1);
    head = (IP_ADAPTER_ADDRESSES *)buf;
    if ((err = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, head,
                                    &buflen)) != ERROR_SUCCESS) {
        char errbuf[300];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                      0, errbuf, sizeof(errbuf), NULL);
        log0(0, 0, 0, "GetAdaptersAddresses failed: (%d) %s", err, errbuf);
        free(buf);
        return;
    }
    for (*len = 0, curr = head; curr; curr = curr->Next) {
        if (curr->IfType == IF_TYPE_TUNNEL) continue;
        for (uni = curr->FirstUnicastAddress; uni; uni = uni->Next) {
            if (curr->OperStatus == IfOperStatusUp) {
                memset(&list[*len], 0, sizeof(struct iflist));
                strncpy(list[*len].name, (char *)curr->AdapterName,
                        sizeof(list[i].name) - 1);
                memcpy(&list[*len].su, uni->Address.lpSockaddr,
                        uni->Address.iSockaddrLength);
                list[*len].isloopback =
                        (curr->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
                list[*len].ismulti =
                        ((curr->Flags & IP_ADAPTER_NO_MULTICAST) == 0);
                if (uni->Address.lpSockaddr->sa_family == AF_INET6) {
                    list[*len].ifidx = curr->Ipv6IfIndex;
                } else {
                    list[*len].ifidx = curr->IfIndex;
                }
                (*len)++;
            }
        }
    }
    free(buf);
}

#else  /*if WINDOWS*/

#include <libgen.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/statvfs.h>

#include "uftp.h"
#include "uftp_common.h"
#include "encryption.h"

#ifdef HAS_GETIFADDRS

#include <ifaddrs.h>

void getiflist(struct iflist *list, int *len)
{
    struct ifaddrs *ifa, *ifa_tmp;
    int count;
    unsigned ifidx;

    if (getifaddrs(&ifa) == -1) {
        syserror(0, 0, 0, "getifaddrs failed");
        *len = 0;
        return;
    }
    ifa_tmp = ifa;
    count = *len;
    *len = 0;
    while (ifa_tmp && (*len < count)) {
        if ((ifidx = if_nametoindex(ifa_tmp->ifa_name)) == 0) {
            syserror(0, 0, 0, "Error getting interface index for interface %s",
                              ifa_tmp->ifa_name);
            continue;
        }
        if (ifa_tmp->ifa_addr && ((ifa_tmp->ifa_addr->sa_family == AF_INET) ||
                                  (ifa_tmp->ifa_addr->sa_family == AF_INET6)) &&
                    ((ifa_tmp->ifa_flags & IFF_UP) != 0)) {
            memset(&list[*len], 0, sizeof(struct iflist));
            strncpy(list[*len].name, ifa_tmp->ifa_name,
                    sizeof(list[*len].name) - 1);
            memcpy(&list[*len].su, ifa_tmp->ifa_addr,
                    sizeof(struct sockaddr_storage));
            list[*len].isloopback = (ifa_tmp->ifa_flags & IFF_LOOPBACK) != 0;
            list[*len].ismulti = (ifa_tmp->ifa_flags & IFF_MULTICAST) != 0;
            list[*len].ifidx = ifidx;
            (*len)++;
        }
        ifa_tmp = ifa_tmp->ifa_next;
    }
    freeifaddrs(ifa);
}

#else

void getiflist(struct iflist *list, int *len)
{
    int s, i, count;
    struct lifconf ifc;
    struct lifreq *ifr, ifr_tmp_flags, ifr_tmp_ifidx;

    if (*len <= 0) return;
    count = *len;
    ifr = safe_malloc(sizeof(struct lifreq) * count);
    ifc.lifc_family = AF_UNSPEC;
    ifc.lifc_flags = 0;
    ifc.lifc_len = sizeof(struct lifreq) * count;
    ifc.lifc_req = ifr;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        sockerror(0, 0, 0, "Error creating socket for interface list");
        free(ifr);
        *len = 0;
        return;
    }
    if (ioctl(s, SIOCGLIFCONF, &ifc) == -1) {
        syserror(0, 0, 0, "Error getting interface list");
        free(ifr);
        close(s);
        *len = 0;
        return;
    }
    count = ifc.lifc_len / sizeof(struct lifreq);
    for (i = 0, *len = 0; i < count; i++) {
        strcpy(ifr_tmp_flags.lifr_name, ifr[i].lifr_name);
        if (ioctl(s, SIOCGLIFFLAGS, &ifr_tmp_flags) == -1) {
            syserror(0, 0, 0, "Error getting flags for interface %s",
                              ifr[i].lifr_name);
            continue;
        }
        strcpy(ifr_tmp_ifidx.lifr_name, ifr[i].lifr_name);
        if (ioctl(s, SIOCGLIFINDEX, &ifr_tmp_ifidx) == -1) {
            syserror(0, 0, 0, "Error getting interface index for interface %s",
                              ifr[i].lifr_name);
            continue;
        }
        if (((ifr[i].lifr_addr.ss_family == AF_INET) ||
                (ifr[i].lifr_addr.ss_family == AF_INET6)) &&
                ((ifr_tmp_flags.lifr_flags & IFF_UP) != 0)) {
            memset(&list[*len], 0, sizeof(struct iflist));
            strncpy(list[*len].name,ifr[i].lifr_name, sizeof(list[i].name) - 1);
            memcpy(&list[*len].su, &ifr[i].lifr_addr,
                    sizeof(struct sockaddr_storage));
            list[*len].isloopback =
                    (ifr_tmp_flags.lifr_flags & IFF_LOOPBACK) != 0;
            list[*len].ismulti = (ifr_tmp_flags.lifr_flags & IFF_MULTICAST)!=0;
            list[*len].ifidx = ifr_tmp_ifidx.lifr_index;
            (*len)++;
        }
    }
    free(ifr);
    close(s);
}

#endif /*if Sun*/

#ifdef VMS
pid_t GENERIC_SETSID(void) { return(0); }
#endif

#endif /*if WINDOWS*/

const char *printll(int64_t n)
{
    static char str[50];

#ifdef WINDOWS
    snprintf(str, sizeof(str) - 1, "%I64d", n);
#else
    snprintf(str, sizeof(str) - 1, "%lld", (long long)n);
#endif
    str[sizeof(str) - 1] = '\x0';
    return &str[0];
}


int32_t diff_sec(struct timeval t2, struct timeval t1)
{
    return t2.tv_sec - t1.tv_sec;
}

int64_t diff_usec(struct timeval t2, struct timeval t1)
{
    return (t2.tv_usec - t1.tv_usec) +
            (int64_t)1000000 * (t2.tv_sec - t1.tv_sec);
}

int cmptimestamp(struct timeval t1, struct timeval t2)
{
    if (t1.tv_sec > t2.tv_sec) {
        return 1;
    } else if (t1.tv_sec < t2.tv_sec) {
        return -1;
    } else if (t1.tv_usec > t2.tv_usec) {
        return 1;
    } else if (t1.tv_usec < t2.tv_usec) {
        return -1;
    } else {
        return 0;
    }
}

struct timeval add_timeval(struct timeval t2, struct timeval t1)
{
    struct timeval result;

    result.tv_sec = t2.tv_sec + t1.tv_sec;
    result.tv_usec = t2.tv_usec + t1.tv_usec;
    while (result.tv_usec >= 1000000) {
        result.tv_usec -= 1000000;
        result.tv_sec++;
    }
    return result;
}

void add_timeval_d(struct timeval *t2, double t1)
{
    t2->tv_sec += (long)(floor(t1) + 0);
    t2->tv_usec += (long)((t1 - floor(t1)) * 1000000);
    while (t2->tv_usec >= 1000000) {
        t2->tv_usec -= 1000000;
        t2->tv_sec++;
    }
}

struct timeval diff_timeval(struct timeval t2, struct timeval t1)
{
    struct timeval result;

    result.tv_sec = t2.tv_sec - t1.tv_sec;
    result.tv_usec = t2.tv_usec - t1.tv_usec;
    while (result.tv_usec < 0) {
        result.tv_usec += 1000000;
        result.tv_sec--;
    }
    return result;
}

/**
 * Gets the name of the UFTP message type for the given message type constant
 */
const char *func_name(int func)
{
    switch (func) {
    case ANNOUNCE:
        return "ANNOUNCE";
    case REGISTER:
        return "REGISTER";
    case CLIENT_KEY:
        return "CLIENT_KEY";
    case REG_CONF:
        return "REG_CONF";
    case KEYINFO:
        return "KEYINFO";
    case KEYINFO_ACK:
        return "KEYINFO_ACK";
    case FILEINFO:
        return "FILEINFO";
    case FILEINFO_ACK:
        return "FILEINFO_ACK";
    case FILESEG:
        return "FILESEG";
    case DONE:
        return "DONE";
    case STATUS:
        return "STATUS";
    case COMPLETE:
        return "COMPLETE";
    case DONE_CONF:
        return "DONE_CONF";
    case HB_REQ:
        return "HB_REQ";
    case HB_RESP:
        return "HB_RESP";
    case KEY_REQ:
        return "KEY_REQ";
    case PROXY_KEY:
        return "PROXY_KEY";
    case ENCRYPTED:
        return "ENCRYPTED";
    case ABORT:
        return "ABORT";
    case CONG_CTRL:
        return "CONG_CTRL";
    case CC_ACK:
        return "CC_ACK";
    default:
        return "UNKNOWN";
  }
}

/**
 * Gets the name of the EC curve for the given EC curve constant.
 */
const char *curve_name(int curve)
{
    switch (curve) {
    case CURVE_sect163k1:
        return "sect163k1";
    case CURVE_sect163r1:
        return "sect163r1";
    case CURVE_sect163r2:
        return "sect163r2";
    case CURVE_sect193r1:
        return "sect193r1";
    case CURVE_sect193r2:
        return "sect193r2";
    case CURVE_sect233k1:
        return "sect233k1";
    case CURVE_sect233r1:
        return "sect233r1";
    case CURVE_sect239k1:
        return "sect239k1";
    case CURVE_sect283k1:
        return "sect283k1";
    case CURVE_sect283r1:
        return "sect283r1";
    case CURVE_sect409k1:
        return "sect409k1";
    case CURVE_sect409r1:
        return "sect409r1";
    case CURVE_sect571k1:
        return "sect571k1";
    case CURVE_sect571r1:
        return "sect571r1";
    case CURVE_secp160k1:
        return "secp160k1";
    case CURVE_secp160r1:
        return "secp160r1";
    case CURVE_secp160r2:
        return "secp160r2";
    case CURVE_secp192k1:
        return "secp192k1";
    case CURVE_secp192r1:
        return "prime192v1";
    case CURVE_secp224k1:
        return "secp224k1";
    case CURVE_secp224r1:
        return "secp224r1";
    case CURVE_secp256k1:
        return "secp256k1";
    case CURVE_secp256r1:
        return "prime256v1";
    case CURVE_secp384r1:
        return "secp384r1";
    case CURVE_secp521r1:
        return "secp521r1";
    default:
        return "UNKNOWN";
    }
}

/**
 * Gets the EC curve constant for the given curve name.
 * Returns 0 if the name is invalid
 */
uint8_t get_curve(const char *name)
{
    if (!strcmp(name, "sect163k1")) {
        return CURVE_sect163k1;
    } else if (!strcmp(name, "sect163r1")) {
        return CURVE_sect163r1;
    } else if (!strcmp(name, "sect163r2")) {
        return CURVE_sect163r2;
    } else if (!strcmp(name, "sect193r1")) {
        return CURVE_sect193r1;
    } else if (!strcmp(name, "sect193r2")) {
        return CURVE_sect193r2;
    } else if (!strcmp(name, "sect233k1")) {
        return CURVE_sect233k1;
    } else if (!strcmp(name, "sect233r1")) {
        return CURVE_sect233r1;
    } else if (!strcmp(name, "sect239k1")) {
        return CURVE_sect239k1;
    } else if (!strcmp(name, "sect283k1")) {
        return CURVE_sect283k1;
    } else if (!strcmp(name, "sect283r1")) {
        return CURVE_sect283r1;
    } else if (!strcmp(name, "sect409k1")) {
        return CURVE_sect409k1;
    } else if (!strcmp(name, "sect409r1")) {
        return CURVE_sect409r1;
    } else if (!strcmp(name, "sect571k1")) {
        return CURVE_sect571k1;
    } else if (!strcmp(name, "sect571r1")) {
        return CURVE_sect571r1;
    } else if (!strcmp(name, "secp160k1")) {
        return CURVE_secp160k1;
    } else if (!strcmp(name, "secp160r1")) {
        return CURVE_secp160r1;
    } else if (!strcmp(name, "secp160r2")) {
        return CURVE_secp160r2;
    } else if (!strcmp(name, "secp192k1")) {
        return CURVE_secp192k1;
    } else if (!strcmp(name, "secp192r1")) {
        return CURVE_secp192r1;
    } else if (!strcmp(name, "secp224r1")) {
        return CURVE_secp224r1;
    } else if (!strcmp(name, "secp256k1")) {
        return CURVE_secp256k1;
    } else if (!strcmp(name, "secp256r1")) {
        return CURVE_secp256r1;
    } else if (!strcmp(name, "secp384r1")) {
        return CURVE_secp384r1;
    } else if (!strcmp(name, "secp521r1")) {
        return CURVE_secp521r1;
    } else if (!strcmp(name, "prime192v1")) {
        return CURVE_prime192v1;
    } else if (!strcmp(name, "prime256v1")) {
        return CURVE_prime256v1;
    } else {
        return 0;
    }
}

char logfile[MAXPATHNAME];
int showtime;
FILE *applog;
int log_level, init_log_mux, use_log_mux, max_log_count;
f_offset_t log_size, max_log_size;
mux_t log_mux;

static int rolling = 0;

/**
 * Initialize the log file.
 */
void init_log(int _debug)
{
    use_log_mux = 0;
    if (init_log_mux) {
        if (mux_create(log_mux)) {
            perror("Failed to create log mutex");
            exit(ERR_LOGGING);
        }
    }

    if (strcmp(logfile, "") && !_debug) {
        int fd;
        stat_struct statbuf;

        if ((lstat_func(logfile, &statbuf) != -1) && S_ISREG(statbuf.st_mode)) {
            log_size = statbuf.st_size;
        } else {
            log_size = 0;
        }
        if ((fd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
            perror("Can't open log file");
            exit(ERR_LOGGING); 
        }
        dup2(fd, 2);
        close(fd);

        showtime = 1;
    } else {
        log_size = 0;
        max_log_size = 0;
        max_log_count = 0;
    }
    applog = stderr;
}

/**
 * Close log file
 */
void close_log()
{
    if (init_log_mux) {
        mux_destroy(log_mux);
    }
    fclose(applog);
}

/**
 * Rolls the log file.
 */
void roll_log()
{
    char oldname[MAXPATHNAME], newname[MAXPATHNAME];
    int rval, fd, i;

    if (rolling) return;
    rolling = 1;
    log2(0, 0, 0, "Rolling logs");
    for (i = max_log_count; i >=0; i--) {
        if (i == 0) {
            rval = snprintf(oldname, sizeof(oldname), "%s", logfile);
            if  (rval >= sizeof(oldname)) {
                log0(0, 0, 0, "Old log name too long");
                rolling = 0;
                return;
            }
        } else {
            rval = snprintf(oldname, sizeof(oldname), "%s.%d", logfile, i);
            if  (rval >= sizeof(oldname)) {
                log0(0, 0, 0, "Old log name too long");
                rolling = 0;
                return;
            }
        }
        rval = snprintf(newname, sizeof(newname), "%s.%d", logfile, i + 1);
        if  (rval >= sizeof(oldname)) {
            log0(0, 0, 0, "New log name too long");
            rolling = 0;
            return;
        }
        if (i == max_log_count) {
            if (unlink(oldname) == -1) {
                syserror(0, 0, 0, "Couldn't remove log %s", oldname);
            }
        } else if (i == 0) {
#ifdef WINDOWS
            log2(0, 0, 0, "Switching to new log");
            close(2);
            if (rename(oldname, newname) == -1) {
                printf("Couldn't rename log %s to %s", oldname, newname);
                exit(ERR_LOGGING);
            }
            if ((fd=open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
                printf("Can't open log file");
                exit(ERR_LOGGING); 
            }
            log_size = 0;
            log2(0, 0, 0, "Switch to new log complete");
#else
            if (rename(oldname, newname) == -1) {
                syserror(0, 0, 0, "Couldn't rename log %s to %s",
                                  oldname, newname);
            }
            log2(0, 0, 0, "Opening new log");
            if ((fd=open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
                syserror(0, 0, 0, "Can't open log file");
                exit(ERR_LOGGING); 
            }
            log2(0, 0, 0, "Switching to new log");
            dup2(fd, 2);
            close(fd);
            log_size = 0;
            log2(0, 0, 0, "Switch to new log complete");
#endif
        } else {
            if (rename(oldname, newname) == -1) {
                syserror(0, 0, 0, "Couldn't rename log %s to %s",
                                  oldname, newname);
            }
        }
    }
    rolling = 0;
}

/**
 * The main logging function.
 * Called via a series of macros for a particular log level or output format.
 */
void logfunc(uint32_t group_id, uint8_t group_inst, uint16_t file_id,
             int level, int _showtime, int newline, int err, int sockerr,
             const char *str, ...)
{
    struct tm *timeval;
    struct timeval tv;
    time_t t;
    va_list args;
    int write_len;
 
    if (level > log_level) return;
    if (use_log_mux && !rolling) {
        if (mux_lock(log_mux)) {
            write_len = fprintf(applog, "Failed to lock log mutex\n");
            if (write_len != -1) log_size += write_len;
        }
    }
    if (_showtime) {
        gettimeofday(&tv, NULL);
        // In Windows, tv.tv_sec is long, not time_t
        t = tv.tv_sec;
        timeval = localtime(&t);
        write_len = fprintf(applog, "%04d/%02d/%02d %02d:%02d:%02d.%06d: ",
                timeval->tm_year + 1900, timeval->tm_mon + 1, timeval->tm_mday,
                timeval->tm_hour, timeval->tm_min, timeval->tm_sec,
                (int)tv.tv_usec);
        if (write_len != -1) log_size += write_len;
        if (group_id) {
            if (file_id) {
                write_len = fprintf(applog, "[%08X/%02X:%04X]: ",
                                    group_id, group_inst, file_id);
            } else {
                write_len = fprintf(applog, "[%08X/%02X:0]: ",
                                    group_id, group_inst);
            }
            if (write_len != -1) log_size += write_len;
        }
    }
    va_start(args, str);
    write_len = vfprintf(applog, str, args);
    if (write_len != -1) log_size += write_len;
    va_end(args);
    if (sockerr) {
#ifdef WINDOWS
        char errbuf[300];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, WSAGetLastError(),
                      0, errbuf, sizeof(errbuf), NULL);
        write_len = fprintf(applog, ": (%d) %s", WSAGetLastError(), errbuf);
        newline = 0;
#else
        write_len = fprintf(applog, ": %s", strerror(err));
#endif
        if (write_len != -1) log_size += write_len;
    } else if (err) {
        write_len = fprintf(applog, ": %s", strerror(err));
        if (write_len != -1) log_size += write_len;
    } 
    if (newline) {
        write_len = fprintf(applog, "\n");
        if (write_len != -1) log_size += write_len;
    }
    fflush(applog);
    if ((max_log_size > 0) && (log_size > max_log_size)) {
        roll_log();
    }
    if (use_log_mux && !rolling) {
        if (mux_unlock(log_mux)) {
            write_len = fprintf(applog, "Failed to unlock log mutex\n");
            if (write_len != -1) log_size += write_len;
            fflush(applog);
        }
    }
}

/**
 * Takes a pathname and splits it into a directory part and file part.
 * The caller is expected to clean up *dir and *file.
 */
void split_path(const char *path, char **dir, char **file)
{
#ifdef WINDOWS
    char *result, *filename;
    DWORD len, len2;

    if (strlen(path) == 0) {
        *dir = NULL;
        *file = NULL;
        return;
    }

    // GetFullPathNameA doens't handle trailing slashes well, so disallow
    if ((path[strlen(path)-1] == '/') || (path[strlen(path)-1] == '\\')) {
        log0(0, 0, 0, "bad path, trailing / or \\ not allowed");
        *dir = NULL;
        *file = NULL;
        return;
    }

    len = GetFullPathNameA(path, 0, NULL, &filename);
    if (len == 0) {
        char errbuf[300];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
                GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
        log0(0, 0, 0, "Error in GetFullPathNameA: %s", errbuf);
        *dir = NULL;
        *file = NULL;
        return;
    }

    *dir = NULL;
    *file = NULL;
    result = safe_malloc(len);
    if ((len2 = GetFullPathNameA(path, len, result, &filename)) <= len) {
        *dir = strdup(result);
        *file = strdup(filename);
        if (!*dir || (filename && !*file)) {
            syserror(0, 0, 0, "strdup failed!");
            exit(ERR_ALLOC);
        }
        (*dir)[strlen(*dir) - strlen(*file) - 1] = '\x0';
    }
    free(result);
#else
    char *dirc, *filec;

    dirc = strdup(path);
    filec = strdup(path);
    if (!dirc || !filec) {
        syserror(0, 0, 0, "strdup failed!");
        exit(ERR_ALLOC);
    }
    *dir = strdup(dirname(dirc));
    *file = strdup(basename(filec));
    if (!*dir || !*file) {
        syserror(0, 0, 0, "strdup failed!");
        exit(ERR_ALLOC);
    }
    free(dirc);
    free(filec);
#endif
}

/**
 * Parses a key fingerprint string and saves it to the specified buffer
 * Returns 1 on success, 0 on fail
 */
int parse_fingerprint(unsigned char *fingerprint, const char *fingerprint_str)
{
    char *p, *tmp;
    int num, len;

    if (fingerprint_str == NULL) {
        return 0;
    }
    tmp = strdup(fingerprint_str);
    len = 0;
    p = strtok(tmp, ":");
    if (p == NULL) {
        log1(0, 0, 0, "Invalid fingerprint %s", fingerprint_str);
        free(tmp);
        return 0;
    }
    do {
        if (len >= HMAC_LEN) {
            log1(0, 0, 0, "Key fingerprint %s too long", fingerprint_str);
            free(tmp);
            return 0;
        }
        errno = 0;
        num = strtol(p, NULL, 16);
        if (errno) {
            syserror(0, 0, 0, "Parse of host key fingerprint %s failed",
                              fingerprint_str);
            free(tmp);
            return 0;
        } else if ((num > 255) || (num < 0)) {
            log1(0, 0, 0, "Parse of host key fingerprint %s failed",
                          fingerprint_str);
            free(tmp);
            return 0;
        }
        fingerprint[len++] = (uint8_t)num;
        p = strtok(NULL, ":");
    } while (p);
    free(tmp);
    return 1;
}

/**
 * Tests a sockaddr_u union to see if it's a valid multicast address
 */
int is_multicast(const union sockaddr_u *addr, int ssm)
{
    int val;

    if (addr->ss.ss_family == AF_INET6) {
        if (addr->sin6.sin6_addr.s6_addr[0] == 0xff) {
            if (ssm && ((addr->sin6.sin6_addr.s6_addr[1] & 0x30) == 0)) {
                return 0;
            } else {
                return 1;
            } 
        } else {
            return 0;
        }
    } else if (addr->ss.ss_family == AF_INET) {
        val = ntohl(addr->sin.sin_addr.s_addr) >> 24;
        if (ssm && (val != 232)) {
            return 0;
        } else if ((val >= 224) && (val < 240)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}

/**
 * Compares two sockaddr_u unions for equality
 * Returns 1 if address family, address, and port are equal, 0 otherwise
 */
int addr_equal(const union sockaddr_u *addr1, const union sockaddr_u *addr2)
{
    if (addr1->ss.ss_family != addr2->ss.ss_family) {
        return 0;
    }
    if (addr1->ss.ss_family == AF_INET6) {
        if ((!memcmp(&addr1->sin6.sin6_addr, &addr2->sin6.sin6_addr,
                    sizeof(struct in6_addr))) &&
                (addr1->sin6.sin6_port == addr2->sin6.sin6_port)) {
            return 1;
        } else {
            return 0;
        }
    } else {
        if ((addr1->sin.sin_addr.s_addr == addr2->sin.sin_addr.s_addr) &&
                (addr1->sin.sin_port == addr2->sin.sin_port)) {
            return 1;
        } else {
            return 0;
        }
    }
}

/**
 * Checks to see if a sockaddr_u union has a zero address
 * Returns 1 if the address is zero (for the given family), 0 otherwise.
 */
int addr_blank(const union sockaddr_u *addr)
{
    if (addr->ss.ss_family == AF_INET6) {
        return (memcmp(&addr->sin6.sin6_addr, &in6addr_any,
                         sizeof(struct in6_addr)) == 0);
    } else if (addr->ss.ss_family == AF_INET) {
        return (addr->sin.sin_addr.s_addr == INADDR_ANY);
    } else {
        return 1;
    }
}

/**
 * Converts a 64-bit value from host to network byte order
 */
uint64_t uftp_htonll(uint64_t val)
{
    uint64_t rval;
    int i;
    unsigned char *p;

    p = (unsigned char *)&rval;
    for (i = 0; i < 8; i++) {
        p[7 - i] = (val & (0xFFLL << (i * 8))) >> (i * 8);
    }
    return rval;
}

/**
 * Converts a 64-bit value from network to host byte order
 */
uint64_t uftp_ntohll(uint64_t val)
{
    uint64_t rval;
    int i;
    unsigned char *p;

    p = (unsigned char *)&val;
    for (i = 0, rval = 0; i < 8; i++) {
        rval |= (uint64_t)p[i] << ((7 - i) * 8);
    }
    return rval;
}

/**
 * Returns the effective length of a sockaddr type struct
 * based on the address family
 */
int family_len(union sockaddr_u addr)
{
    if (addr.ss.ss_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    } else if (addr.ss.ss_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else {
        return sizeof(struct sockaddr_storage);
    }
}

/**
 * Returns whether the last socket operation would have blocked
 */
int would_block_err()
{
#ifdef WINDOWS
    return (WSAGetLastError() == WSAEWOULDBLOCK);
#else
    return (errno == EAGAIN);
#endif
}

/**
 * Returns whether a connection reset error occurred
 */
int conn_reset_err(void)
{
#ifdef WINDOWS
    return (WSAGetLastError() == WSAECONNRESET);
#else
    return (errno == ECONNRESET);
#endif
}

/**
 * Calls sendto, retrying if the send would block.
 * The calling function should check for and log any other errors.
 */
int nb_sendto(SOCKET s, const void *msg, int len, int flags,
              const struct sockaddr *to, int tolen)
{
    int retry, sentlen;

    retry = 1;
    while (retry) {
        if ((sentlen = sendto(s, msg, len, flags, to, tolen)) == SOCKET_ERROR) {
            if (!would_block_err()) {
                return -1;
            }
        } else {
            retry = 0;
        }
    }
    return sentlen;
}

/**
 * Reads a packet off the network with a possible timeout.
 * The socket must be non-blocking.
 * Returns 1 on success, 0 on timeout, -1 on fail.
 */
int read_packet(SOCKET sock, union sockaddr_u *su, unsigned char *buffer,
                int *len, int bsize, const struct timeval *timeout,
                uint8_t *tos)
{
    fd_set fdin;
    struct timeval tv;
    int rval;
#ifdef WINDOWS
    GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
    static LPFN_WSARECVMSG WSARecvMsg;
    int nbytes;
    WSAMSG mhdr;
    WSABUF iov;
    WSACMSGHDR *cmhdr;
    char control[1000];
#elif defined NO_RECVMSG
    socklen_t addr_len;
#else
    struct msghdr mhdr;
    struct iovec iov;
    struct cmsghdr *cmhdr;
    char control[1000];
#endif

    while (1) {
#ifdef WINDOWS
        if (WSARecvMsg == NULL) {
            rval = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
                    &WSARecvMsg, sizeof WSARecvMsg, &nbytes, NULL, NULL);
            if (rval == SOCKET_ERROR) {
                sockerror(0, 0, 0, "WSAIoctl for WSARecvMsg failed");
                exit(ERR_SOCKET);
            }
        }
        mhdr.name = (LPSOCKADDR)su;
        mhdr.namelen = sizeof(union sockaddr_u);
        mhdr.lpBuffers = &iov;
        mhdr.dwBufferCount = 1;
        mhdr.Control.buf = control;
        mhdr.Control.len = sizeof(control);
        mhdr.dwFlags = 0;
        iov.buf = buffer;
        iov.len = bsize;
        if ((rval = WSARecvMsg(sock, &mhdr, len, NULL, NULL)) == SOCKET_ERROR) {
            if (!would_block_err()) {
                if (!conn_reset_err()) {
                    sockerror(0, 0, 0, "Error receiving");
                }
                return -1;
            }
        } else {
            *tos = 0;
            cmhdr = WSA_CMSG_FIRSTHDR(&mhdr);
            while (cmhdr) {
                if ((cmhdr->cmsg_level == IPPROTO_IP &&
                        cmhdr->cmsg_type == IP_TCLASS) ||
                        (cmhdr->cmsg_level == IPPROTO_IPV6 &&
                         cmhdr->cmsg_type == IPV6_TCLASS)) {
                    *tos = ((uint8_t *)WSA_CMSG_DATA(cmhdr))[0];
                }
                cmhdr = WSA_CMSG_NXTHDR(&mhdr, cmhdr);
            }
            log5(0, 0, 0, "tos / traffic class byte = %02X", *tos);
            return 1;
        }
#elif defined NO_RECVMSG
        addr_len = sizeof(union sockaddr_u);
        if ((*len = recvfrom(sock, buffer, bsize, 0, (struct sockaddr *)su,
                             &addr_len)) == SOCKET_ERROR) {
            if (!would_block_err()) {
                if (!conn_reset_err()) {
                    sockerror(0, 0, 0, "Error receiving");
                }
                return -1;
            }
        } else {
            return 1;
        }
#else
        mhdr.msg_name = su;
        mhdr.msg_namelen = sizeof(union sockaddr_u);
        mhdr.msg_iov = &iov;
        mhdr.msg_iovlen = 1;
        mhdr.msg_control = &control;
        mhdr.msg_controllen = sizeof(control);
        iov.iov_base = buffer;
        iov.iov_len = bsize;
        if ((*len = recvmsg(sock, &mhdr, 0)) == SOCKET_ERROR) {
            if (!would_block_err()) {
                if (!conn_reset_err()) {
                    sockerror(0, 0, 0, "Error receiving");
                }
                return -1;
            }
        } else {
            *tos = 0;
            cmhdr = CMSG_FIRSTHDR(&mhdr);
            while (cmhdr) {
                int istos;
#ifdef IP_RECVTOS
#if defined IPV6_TCLASS && !defined WINDOWS
                istos = ((cmhdr->cmsg_level == IPPROTO_IP &&
                        (cmhdr->cmsg_type == IP_TOS ||
                        cmhdr->cmsg_type == IP_RECVTOS)) ||
                        (cmhdr->cmsg_level == IPPROTO_IPV6 &&
                         cmhdr->cmsg_type == IPV6_TCLASS));
#else
                istos = (cmhdr->cmsg_level == IPPROTO_IP &&
                        (cmhdr->cmsg_type == IP_TOS ||
                        cmhdr->cmsg_type == IP_RECVTOS));
#endif
#else  // IP_RECVTOS
#if defined IPV6_TCLASS && !defined WINDOWS
                istos = ((cmhdr->cmsg_level == IPPROTO_IP &&
                        cmhdr->cmsg_type == IP_TOS) ||
                        (cmhdr->cmsg_level == IPPROTO_IPV6 &&
                         cmhdr->cmsg_type == IPV6_TCLASS));
#else
                istos = (cmhdr->cmsg_level == IPPROTO_IP &&
                        cmhdr->cmsg_type == IP_TOS);
#endif
#endif  // IP_RECVTOS
                if (istos) {
                    *tos = ((uint8_t *)CMSG_DATA(cmhdr))[0];
                }
                cmhdr = CMSG_NXTHDR(&mhdr, cmhdr);
            }
            log5(0, 0, 0, "tos / traffic class byte = %02X", *tos);
            return 1;
        }
#endif

        FD_ZERO(&fdin);
        FD_SET(sock,&fdin);
        if (timeout) tv = *timeout;
        if ((rval = select(FD_SETSIZE-1, &fdin, NULL, NULL,
                           (timeout ? &tv : NULL))) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Select failed");
            return -1;
        }
        if (rval == 0) {
            return 0;
        } else if (!FD_ISSET(sock, &fdin)) {
            log0(0, 0, 0, "Unknown select error");
            return -1;
        }
    }
}

/**
 * Performs an XOR between p1 and p2, storing the result in p1
 */
void memxor(void *p1, const void *p2, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        ((unsigned char *)p1)[i] ^= ((const unsigned char *)p2)[i];
    }
}

/**
 * Constructs an initialization vector (IV) as follows:
 * For a 128-bit IV (AES non-auth): IV = S + src_ID + ctr
 * For a 96-bit IV (AES auth):      IV = (S XOR src_ID) + ctr
 * For a 64-bit IV (DES, 3DES):     IV = (S + src_ID) XOR ctr
 * All values other should be in network byte order.
 */
void build_iv(uint8_t *iv, const uint8_t *salt, int ivlen, uint64_t ivctr,
              uint32_t src_id)
{
    char tmp[16], tmp2[16];
    int tmplen, tmp2len;

    memset(tmp, 0, sizeof(tmp));
    tmplen = 0;
    if (ivlen == 8) {
        memcpy(tmp, salt, SALT_LEN);
        tmplen = SALT_LEN;
        memcpy(tmp + tmplen, &src_id, sizeof(uint32_t));
        tmplen += sizeof(uint32_t);
        memcpy(tmp2, &ivctr, sizeof(uint64_t));
        tmp2len = sizeof(uint64_t);
        memxor(tmp, tmp2, tmp2len);
    } else if (ivlen == 12) {
        memcpy(tmp, salt, SALT_LEN);
        tmplen = SALT_LEN;
        memcpy(tmp2, &src_id, sizeof(uint32_t));
        tmp2len = sizeof(uint32_t);
        memxor(tmp, tmp2, tmp2len);
        memcpy(tmp + tmplen, &ivctr, sizeof(uint64_t));
        tmplen += sizeof(uint64_t);
    } else if (ivlen == 16) {
        memcpy(tmp, salt, SALT_LEN);
        tmplen = SALT_LEN;
        memcpy(tmp + tmplen, &src_id, sizeof(uint32_t));
        tmplen += sizeof(uint32_t);
        memcpy(tmp + tmplen, &ivctr, sizeof(uint64_t));
        tmplen += sizeof(uint64_t);
    }
    memcpy(iv, tmp, tmplen);
}

/**
 * Outputs data buffers to log in hex.
 * Used only for debugging
 */
void printhex(const char *name, const unsigned char *data, int len)
{
    int i;

    sclog2("%s:", name);
    for (i = 0; i < len; i++) {
        sclog2(" %02X", data[i]);
        if (i % 16 == 15) sclog2("\n");
    }
    sclog2("\n");
}

/**
 * Returns 1 if the specified keytype is an authentication mode cipher
 */
int is_auth_enc(int keytype)
{
    return ((keytype == KEY_AES128_GCM) || (keytype == KEY_AES256_GCM) ||
            (keytype == KEY_AES128_CCM) || (keytype == KEY_AES256_CCM));
}

/**
 * Returns 1 if the specified keytype is a GCM mode cipher
 */
int is_gcm_mode(int keytype)
{
    return ((keytype == KEY_AES128_GCM) || (keytype == KEY_AES256_GCM));
}

/**
 * Returns 1 if the specified keytype is a CCM mode cipher
 */
int is_ccm_mode(int keytype)
{
    return ((keytype == KEY_AES128_CCM) || (keytype == KEY_AES256_CCM));
}

/**
 * If the specified keytype is for an authentication cipher,
 * return the keytype for the same cipher in CBC mode.
 */
int unauth_key(int keytype)
{
    switch (keytype) {
    case KEY_AES128_GCM:
    case KEY_AES128_CCM:
        return KEY_AES128_CBC;
    case KEY_AES256_GCM:
    case KEY_AES256_CCM:
        return KEY_AES256_CBC;
    default:
        return keytype;
    }
}

/**
 * Verify the signature of an encrypted message and decrypt.
 * The decrypted message is returned without a uftp_h header.
 * Returns 1 on success, 0 on fail
 */
int validate_and_decrypt(unsigned char *encpacket, unsigned int enclen,
                         unsigned char **decpacket, unsigned int *declen,
                         int keytype, const uint8_t *key,
                         const uint8_t *salt, int ivlen, int hashtype,
                         const uint8_t *hmackey, uint8_t hmaclen, int sigtype,
                         int keyextype, union key_t pubkey, int pubkeylen)
{
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    unsigned char *payload, *sig, *sigcopy, *sigtest, *iv;
    unsigned int hsiglen, siglen, len, rval, allocdec;
    uint64_t ivctr;

    if (sigtype == SIG_HMAC) {
        siglen = hmaclen;
    } else if (sigtype == SIG_KEYEX) {
        siglen = pubkeylen;
    } else if (sigtype == SIG_AUTHENC) {
        siglen = 0;
    } else {
        log0(0, 0, 0, "Invalid signature type");
        return 0;
    }

    header = (struct uftp_h *)encpacket;
    encrypted = (struct encrypted_h *)(encpacket + sizeof(struct uftp_h));
    hsiglen = ntohs(encrypted->sig_len);
    sig = (unsigned char *)encrypted + sizeof(struct encrypted_h);
    payload = sig + hsiglen;

    if (header->func != ENCRYPTED) {
        log0(0, 0, 0, "Attempt to decrypt non-encrypted message");
        return 0;
    }
    if (enclen != (sizeof(struct uftp_h) + sizeof(struct encrypted_h) +
            hsiglen + ntohs(encrypted->payload_len))) {
        log0(0, 0, 0, "Invalid signature and/or encrypted payload length");
        return 0;
    }
    if (hsiglen != siglen) {
        log0(0, 0, 0, "Signature length incorrect: got %d, expected %d",
                      hsiglen, siglen);
        return 0;
    }

    sigcopy = safe_calloc(siglen, 1);
    sigtest = safe_calloc(siglen, 1);
    iv = safe_calloc(ivlen, 1);

    if (sigtype != SIG_AUTHENC) {
        memcpy(sigcopy, sig, hsiglen);
        memset(sig, 0, hsiglen);
    }
    if (sigtype == SIG_HMAC) {
        if (!create_hmac(hashtype, hmackey, hsiglen, encpacket, enclen,
                         sigtest, &len)) {
            log0(0, 0, 0, "HMAC creation failed");
            rval = 0;
            goto end;
        }
        if (memcmp(sigtest, sigcopy, len)) {
            log0(0, 0, 0, "HMAC verification failed");
            rval = 0;
            goto end;
        }
    } else if ((sigtype == SIG_KEYEX) && (keyextype == KEYEX_ECDH_ECDSA)) {
        if (!verify_ECDSA_sig(pubkey.ec, hashtype, encpacket, enclen,
                              sigcopy, ntohs(encrypted->sig_len))) {
            log0(0, 0, 0, "ECDSA signature verification failed");
            rval = 0;
            goto end;
        }
    } else if ((sigtype == SIG_KEYEX) &&
            ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA))) {
        if (!verify_RSA_sig(pubkey.rsa, hashtype, encpacket, enclen,
                            sigcopy, ntohs(encrypted->sig_len))) {
            log0(0, 0, 0, "RSA signature verification failed");
            rval = 0;
            goto end;
        }
    }

    allocdec = 0;
    if (*decpacket == NULL) {
        allocdec = 1;
        *decpacket = safe_calloc(MAXMTU + KEYBLSIZE, 1);
    }
    ivctr = ntohl(encrypted->iv_ctr_lo);
    ivctr |= (uint64_t)ntohl(encrypted->iv_ctr_hi) << 32;
    build_iv(iv, salt, ivlen, uftp_htonll(ivctr), header->src_id);
    if (!decrypt_block(keytype, iv, key, encpacket,
            sizeof(struct uftp_h) + sizeof(struct encrypted_h),
            payload, ntohs(encrypted->payload_len), *decpacket, declen)) {
        log0(0, 0, 0, "Decrypt failed");
        if (allocdec) {
            free(*decpacket);
            *decpacket = NULL;
        }
        rval = 0;
        goto end;
    }

    rval = 1;

end:
    free(sigcopy);
    free(sigtest);
    free(iv);
    return rval;
}

/**
 * Encrypts a message and attaches a signature to the encrypted message.
 * The incoming message should include a uftp_h header.
 * Returns 1 on success, 0 on fail
 */
int encrypt_and_sign(const unsigned char *decpacket, unsigned char **encpacket,
                     int declen, int *enclen, int keytype, uint8_t *key, 
                     const uint8_t *salt, uint64_t *ivctr, int ivlen,
                     int hashtype, uint8_t *hmackey, uint8_t hmaclen,
                     int sigtype, int keyextype, union key_t privkey,
                     int privkeylen)
{
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    const unsigned char *mheader;
    unsigned char *payload, *sig, *sigcopy, *iv;
    unsigned int payloadlen, siglen, len, allocenc;

    if (sigtype == SIG_HMAC) {
        siglen = hmaclen;
    } else if (sigtype == SIG_KEYEX) {
        siglen = privkeylen;
    } else if (sigtype == SIG_AUTHENC) {
        siglen = 0;
    } else {
        log0(0, 0, 0, "Invalid signature type");
        return 0;
    }

    allocenc = 0;
    if (*encpacket == NULL) {
        allocenc = 1;
        *encpacket = safe_calloc(MAXMTU + KEYBLSIZE, 1);
    }
    iv = safe_calloc(ivlen, 1);

    mheader = decpacket + sizeof(struct uftp_h);
    header = (struct uftp_h *)*encpacket;
    encrypted = (struct encrypted_h *)(*encpacket + sizeof(struct uftp_h));
    sig = (unsigned char *)encrypted + sizeof(struct encrypted_h);
    payload = sig + siglen;

    (*ivctr)++;
    memcpy(*encpacket, decpacket, sizeof(struct uftp_h));
    header->func = ENCRYPTED;
    encrypted->iv_ctr_hi = htonl((*ivctr & 0xFFFFFFFF00000000LL) >> 32);
    encrypted->iv_ctr_lo = htonl(*ivctr & 0x00000000FFFFFFFFLL);
    encrypted->sig_len = htons(siglen);
    if (sigtype == SIG_AUTHENC) {
        if (is_gcm_mode(keytype)) {
            encrypted->payload_len = htons(declen + GCM_TAG_LEN);
        } else if (is_ccm_mode(keytype)) {
            encrypted->payload_len = htons(declen + CCM_TAG_LEN);
        }
    }

    build_iv(iv, salt, ivlen, uftp_htonll(*ivctr), header->src_id);
    if (!encrypt_block(keytype, iv, key, *encpacket,
            sizeof(struct uftp_h) + sizeof(struct encrypted_h),
            mheader, declen, payload, &payloadlen)) {
        // Called function should log
        free(iv);
        if (allocenc) {
            free(*encpacket);
            *encpacket = NULL;
        }
        return 0;
    }
    free(iv);
    if (sigtype != SIG_AUTHENC) {
        encrypted->payload_len = htons(payloadlen);
    } else {
        if (payloadlen != ntohs(encrypted->payload_len)) {
            log0(0, 0, 0, "Invalid payloadlen: got %d, expected %d",
                          payloadlen, ntohs(encrypted->payload_len));
            return 0;
        }
    }
    *enclen = sizeof(struct encrypted_h) + payloadlen + siglen;

    sigcopy = safe_calloc(siglen, 1);
    if (sigtype != SIG_AUTHENC) {
        memset(sig, 0, siglen);
    }
    if (sigtype == SIG_HMAC) {
        if (!create_hmac(hashtype, hmackey, siglen, *encpacket,
                         sizeof(struct uftp_h) + *enclen, sigcopy, &len)) {
            log0(0, 0, 0, "HMAC creation failed");
            free(sigcopy);
            if (allocenc) {
                free(*encpacket);
                *encpacket = NULL;
            }
            return 0;
        }
    } else if ((sigtype == SIG_KEYEX) && (keyextype == KEYEX_ECDH_ECDSA)) {
        if (!create_ECDSA_sig(privkey.ec, hashtype, *encpacket,
                             sizeof(struct uftp_h) + *enclen, sigcopy, &len)) {
            // Called function should log
            free(sigcopy);
            if (allocenc) {
                free(*encpacket);
                *encpacket = NULL;
            }
            return 0;
        }
    } else if ((sigtype == SIG_KEYEX) &&
            ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA))) {
        if (!create_RSA_sig(privkey.rsa, hashtype, *encpacket,
                            sizeof(struct uftp_h) + *enclen, sigcopy, &len)) {
            // Called function should log
            free(sigcopy);
            if (allocenc) {
                free(*encpacket);
                *encpacket = NULL;
            }
            return 0;
        }
    }
    if (sigtype != SIG_AUTHENC) {
        memcpy(sig, sigcopy, len);
    }

    free(sigcopy);
    return 1;
}

/**
 * Pseudo-random function for an individual hashing algorithm
 * as defined in RFC 4346 and RFC 5246
 */
static void P_hash(int hashtype, int bytes, 
                   const unsigned char *secret, int secret_len, 
                   const char *label, const unsigned char *seed, int seed_len,
                   unsigned char *outbuf, int *outbuf_len)
{
    unsigned char *newseed, *inbuf, *tmpbuf;
    unsigned newseed_len, inbuf_len;
    unsigned int tmpbuf_len, outbuf_len_new;

    newseed = safe_calloc(strlen(label) + seed_len, 1);
    inbuf = safe_calloc(get_hash_len(hashtype) + strlen(label) + seed_len, 1);
    tmpbuf = safe_calloc(get_hash_len(hashtype) + strlen(label) + seed_len, 1);

    *outbuf_len = 0;
    newseed_len = 0;
    memcpy(newseed, label, strlen(label));
    newseed_len += strlen(label);
    memcpy(newseed + newseed_len, seed, seed_len);
    newseed_len += seed_len;

    memcpy(inbuf, newseed, newseed_len);
    inbuf_len = newseed_len;
    while (*outbuf_len < bytes)
    {
        // TODO: create_hmac can fail under CrypoAPI.
        // Figure out how to handle this.
        create_hmac(hashtype, secret, secret_len, inbuf, inbuf_len,
                    tmpbuf, &tmpbuf_len);
        memcpy(tmpbuf + tmpbuf_len, newseed, newseed_len);
        tmpbuf_len += newseed_len;
        create_hmac(hashtype, secret, secret_len, tmpbuf, tmpbuf_len, 
                    outbuf + *outbuf_len, &outbuf_len_new);
        *outbuf_len += outbuf_len_new;
        memcpy(inbuf,tmpbuf,tmpbuf_len);
        inbuf_len = tmpbuf_len;
    }

    free(newseed);
    free(inbuf);
    free(tmpbuf);
}

/**
 * Pseudo-random function
 * as defined in RFC 4346 and RFC 5246
 */
void PRF(int hashtype, int bytes, const unsigned char *secret, int secret_len, 
         const char *label, const unsigned char *seed, int seed_len,
         unsigned char *outbuf, int *outbuf_len)
{
    int i, s_len, sha_buf_len, md5_buf_len;
    unsigned char *sha_buf, *md5_buf;

    if (hashtype == HASH_SHA256) {
        P_hash(HASH_SHA256, bytes, secret, secret_len, label,
               seed, seed_len, outbuf, outbuf_len);
    } else if (hashtype == HASH_SHA1) {
        // TLS 1.1 MD5/SHA1 combination
        md5_buf = safe_calloc(bytes + get_hash_len(HASH_MD5), 1);
        sha_buf = safe_calloc(bytes + get_hash_len(HASH_SHA1), 1);
        // if secret_len is even integer division truncates the result
        // if secret_len is odd, the + 1 effectively rounds up
        s_len = (secret_len + 1) / 2;
        P_hash(HASH_MD5, bytes, secret, s_len, label,
               seed, seed_len, md5_buf, &md5_buf_len);
        P_hash(HASH_SHA1, bytes, secret + (secret_len - s_len), s_len, label,
               seed, seed_len, sha_buf, &sha_buf_len);
        for (i = 0; i < bytes; i++) {
            outbuf[i] = md5_buf[i] ^ sha_buf[i];
        }
        *outbuf_len = bytes;
        free(md5_buf);
        free(sha_buf);
    } else {
        *outbuf_len = 0;
    }
}

/**
 * Outputs a key's fingerprint
 */
const char *print_key_fingerprint(const union key_t key, int keytype)
{
    static char fpstr[100];
    char *p;
    unsigned char *keyblob, fingerprint[HMAC_LEN];
    uint16_t bloblen;
    unsigned int fplen, i, cnt;

    keyblob = safe_calloc(PUBKEY_LEN, 1);

    if (keytype == KEYBLOB_RSA) {
        if (!export_RSA_key(key.rsa, keyblob, &bloblen)) {
            free(keyblob);
            return NULL;
        }
    } else {
        if (!export_EC_key(key.ec, keyblob, &bloblen)) {
            free(keyblob);
            return NULL;
        }
    }
    hash(HASH_SHA1, keyblob, bloblen, fingerprint, &fplen);

    for (i = 0, p = fpstr; i < fplen; i++) {
        if (i != 0) {
            *p = ':';
            p++;
        }
        cnt = snprintf(p, 3, "%02X", fingerprint[i]);
        p += cnt;
    }

    free(keyblob);
    return fpstr;
}

#if ((!defined WINDOWS) && (defined MCAST_JOIN_GROUP))

/**
 * Join the specified multicast group on the specified list of interfaces.
 * If source specific multicast is supported and we're given a list of servers,
 * join source specific multicast groups for those servers.
 * Returns 1 on success, 0 on fail
 */
int multicast_join(SOCKET s, uint32_t group_id, const union sockaddr_u *multi,
                   const struct iflist *addrlist, int addrlen,
                   const struct fp_list_t *fplist, int fplist_len)
{
    struct group_req greq;
    struct group_source_req gsreq;
    int level, i, j;

    for (i = 0; i < addrlen; i++) {
        if (!addrlist[i].ismulti) {
            continue;
        }
        if (addrlist[i].su.ss.ss_family != multi->ss.ss_family) {
            continue;
        }
        if (addrlist[i].su.ss.ss_family == AF_INET6) {
            level = IPPROTO_IPV6;
        } else if (addrlist[i].su.ss.ss_family == AF_INET) {
            level = IPPROTO_IP;
        }
        if (fplist_len == 0) {
            greq.gr_interface = addrlist[i].ifidx;
            greq.gr_group = multi->ss;
            if (setsockopt(s, level, MCAST_JOIN_GROUP,
                    (char *)&greq, sizeof(greq)) == -1) {
                sockerror(group_id, 0, 0, "Error joining multicast group"); 
                return 0;
            }
        } else {
            for (j = 0; j < fplist_len; j++) {
                if (addrlist[i].su.ss.ss_family!=fplist[j].addr.ss.ss_family) {
                    continue;
                }
                gsreq.gsr_interface = addrlist[i].ifidx;
                gsreq.gsr_source = fplist[j].addr.ss;
                gsreq.gsr_group = multi->ss;
                if (setsockopt(s, level, MCAST_JOIN_SOURCE_GROUP,
                        (char *)&gsreq, sizeof(gsreq)) == -1) {
                    sockerror(group_id, 0, 0, "Error joining multicast group");
                    return 0;
                }
            }
        }
    }
    return 1;
}

/**
 * Leave the specified multicast group on the specified list of interfaces.
 * If source specific multicast is supported and we're given a list of servers,
 * leave source specific multicast groups for those servers.
 */
void multicast_leave(SOCKET s, uint32_t group_id, const union sockaddr_u *multi,
                     const struct iflist *addrlist, int addrlen,
                     const struct fp_list_t *fplist, int fplist_len)
{
    struct group_req greq;
    struct group_source_req gsreq;
    int level, i, j;

    for (i = 0; i < addrlen; i++) {
        if (!addrlist[i].ismulti) {
            continue;
        }
        if (addrlist[i].su.ss.ss_family != multi->ss.ss_family) {
            continue;
        }
        if (addrlist[i].su.ss.ss_family == AF_INET6) {
            level = IPPROTO_IPV6;
        } else if (addrlist[i].su.ss.ss_family == AF_INET) {
            level = IPPROTO_IP;
        }
        if (fplist_len == 0) {
            greq.gr_interface = addrlist[i].ifidx;
            greq.gr_group = multi->ss;
            if (setsockopt(s, level, MCAST_LEAVE_GROUP,
                    (char *)&greq, sizeof(greq)) == -1) {
                sockerror(group_id, 0, 0, "Error leaving multicast group");
            }
        } else {
            for (j = 0; j < fplist_len; j++) {
                if (addrlist[i].su.ss.ss_family!=fplist[j].addr.ss.ss_family) {
                    continue;
                }
                gsreq.gsr_interface = addrlist[i].ifidx;
                gsreq.gsr_source = fplist[j].addr.ss;
                gsreq.gsr_group = multi->ss;
                if (setsockopt(s, level, MCAST_LEAVE_SOURCE_GROUP,
                        (char *)&gsreq, sizeof(gsreq)) == -1) {
                    sockerror(group_id, 0, 0, "Error leaving multicast group");
                }
            }
        }
    }
}

#else

/**
 * Join the specified multicast group on the specified list of interfaces.
 * If source specific multicast is supported and we're given a list of servers,
 * join source specific multicast groups for those servers.
 * Returns 1 on success, 0 on fail
 */
int multicast_join(SOCKET s, uint32_t group_id, const union sockaddr_u *multi,
                   const struct iflist *addrlist, int addrlen,
                   const struct fp_list_t *fplist, int fplist_len)
{
    struct ip_mreq mreq;
    struct ipv6_mreq mreq6;
    int i;

    for (i = 0; i < addrlen; i++) {
        if (!addrlist[i].ismulti) {
            continue;
        }
        if (addrlist[i].su.ss.ss_family != multi->ss.ss_family) {
            continue;
        }
        if (multi->ss.ss_family == AF_INET6) {
            mreq6.ipv6mr_multiaddr = multi->sin6.sin6_addr;
            mreq6.ipv6mr_interface = addrlist[i].ifidx;
            if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                           (char *)&mreq6, sizeof(mreq6)) == SOCKET_ERROR) {
                sockerror(group_id, 0, 0, "Error joining multicast group");
                return 0;
            }
        } else {
#ifdef IP_ADD_SOURCE_MEMBERSHIP
            if (fplist_len != 0) {
                int j;
                for (j = 0; j < fplist_len; j++) {
                    struct ip_mreq_source srcmreq;
                    srcmreq.imr_multiaddr = multi->sin.sin_addr;
                    srcmreq.imr_sourceaddr = fplist[j].addr.sin.sin_addr;
                    srcmreq.imr_interface = addrlist[i].su.sin.sin_addr;
                    if (setsockopt(s, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP,
                           (char *)&srcmreq, sizeof(srcmreq)) == SOCKET_ERROR) {
                        sockerror(group_id, 0, 0,
                                  "Error joining multicast group");
                        return 0;
                    }
                }
            } else {
                mreq.imr_multiaddr = multi->sin.sin_addr;
                mreq.imr_interface = addrlist[i].su.sin.sin_addr;
                if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                               (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
                    sockerror(group_id, 0, 0, "Error joining multicast group");
                    return 0;
                }
            }
#else
            mreq.imr_multiaddr = multi->sin.sin_addr;
            mreq.imr_interface = addrlist[i].su.sin.sin_addr;
            if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
                sockerror(group_id, 0, 0, "Error joining multicast group");
                return 0;
            }
#endif
        }
    }
    return 1;
}

/**
 * Leave the specified multicast group on the specified list of interfaces.
 * If source specific multicast is supported and we're given a list of servers,
 * leave source specific multicast groups for those servers.
 */
void multicast_leave(SOCKET s, uint32_t group_id, const union sockaddr_u *multi,
                     const struct iflist *addrlist, int addrlen,
                     const struct fp_list_t *fplist, int fplist_len)
{
    struct ip_mreq mreq;
    struct ipv6_mreq mreq6;
    int i;

    for (i = 0; i < addrlen; i++) {
        if (!addrlist[i].ismulti) {
            continue;
        }
        if (addrlist[i].su.ss.ss_family != multi->ss.ss_family) {
            continue;
        }
        if (multi->ss.ss_family == AF_INET6) {
            mreq6.ipv6mr_multiaddr = multi->sin6.sin6_addr;
            mreq6.ipv6mr_interface = addrlist[i].ifidx;
            if (setsockopt(s, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                           (char *)&mreq6, sizeof(mreq6)) == SOCKET_ERROR) {
                sockerror(group_id, 0, 0, "Error leaving multicast group");
            }
        } else {
#ifdef IP_DROP_SOURCE_MEMBERSHIP
            if (fplist_len != 0) {
                int j;
                for (j = 0; j < fplist_len; j++) {
                    struct ip_mreq_source srcmreq;
                    srcmreq.imr_multiaddr = multi->sin.sin_addr;
                    srcmreq.imr_sourceaddr = fplist[j].addr.sin.sin_addr;
                    srcmreq.imr_interface = addrlist[i].su.sin.sin_addr;
                    if (setsockopt(s, IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP,
                           (char *)&srcmreq, sizeof(srcmreq)) == SOCKET_ERROR) {
                        sockerror(group_id, 0, 0,
                                  "Error leaving multicast group");
                    }
                }
            } else {
                mreq.imr_multiaddr = multi->sin.sin_addr;
                mreq.imr_interface = addrlist[i].su.sin.sin_addr;
                if (setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                               (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
                    sockerror(group_id, 0, 0, "Error leaving multicast group");
                }
            }
#else
            mreq.imr_multiaddr = multi->sin.sin_addr;
            mreq.imr_interface = addrlist[i].su.sin.sin_addr;
            if (setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                           (char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
                sockerror(group_id, 0, 0, "Error leaving multicast group");
            }
#endif
        }
    }
}

#endif // MCAST_JOIN_GROUP

/**
 * Search for a network interface in a list with the matching name or index.
 * The name is formatted as interface/ip_version, ex. eth0/6, 2/4.
 * If ip_version is not given, defaults to IPv4.
 * Returns the index in the list if found, -1 if not found.
 */
int getifbyname(const char *name, const struct iflist *list, int len)
{
    char *tmpname, *p, *ptr;
    int family, idx, i;

    tmpname = strdup(name);
    if (tmpname == NULL) {
        syserror(0, 0, 0, "strdup failed!");
        exit(ERR_ALLOC);
    }

    p = strchr(tmpname, '/');
    if (p == NULL) {
        family = AF_INET;
    } else {
        p[0] = 0;
        if (p[1] == '6') {
            family = AF_INET6;
        } else if (p[1] == '4') {
            family = AF_INET;
        } else {
            free(tmpname);
            return -1;
        }
    }

    errno = 0;
    idx = strtoul(tmpname, &ptr, 10);
    if ((errno == 0) && (*ptr == '\x0')) {
        for (i = 0; i < len; i++) {
            if ((idx == list[i].ifidx) && (list[i].su.ss.ss_family == family)) {
                free(tmpname);
                return i;
            }
        }
    } else {
        for (i = 0; i < len; i++) {
            if ((!strcmp(tmpname, list[i].name)) &&
                    (list[i].su.ss.ss_family == family)) {
                free(tmpname);
                return i;
            }
        }
    }
    free(tmpname);
    return -1;
}

/**
 * Search for a network interface in a list with the matching IP address.
 * Returns the index in the list if found, -1 if not found.
 */
int getifbyaddr(union sockaddr_u *su, const struct iflist *list, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (su->ss.ss_family == list[i].su.ss.ss_family) {
            if (su->ss.ss_family == AF_INET) {
                if (su->sin.sin_addr.s_addr == list[i].su.sin.sin_addr.s_addr) {
                    return i;
                }
            } else if (su->ss.ss_family == AF_INET6) {
                if (!memcmp(&su->sin6.sin6_addr, &list[i].su.sin6.sin6_addr,
                        sizeof(struct in6_addr))) {
                    return i;
                }
            }
        }
    }
    return -1;
}

/**
 * Reads buflen bytes into buf from the given file descriptor.
 * If buflen bytes are read, returns buflen.
 * If 0 bytes are read, returns 0 if allow_eof is true, otherwise returns -1.
 * If less that buflen bytes are read, or on error, returns -1.
 */
int file_read(int fd, void *buf, int buflen, int allow_eof)
{
    int read_len;

    if ((read_len = read(fd, buf, buflen)) == -1) {
        syserror(0, 0, 0, "Read failed");
        return -1;
    }
    if ((read_len != buflen) && (!allow_eof || (read_len != 0))) {
        log0(0,0,0, "Read error: read %d bytes, expected %d", read_len, buflen);
        return -1;
    }
    return read_len;
}
/**
 * Writes buflen bytes from buf to the given file descriptor.
 * If buflen bytes are written, returns buflen.
 * If less that buflen bytes are written, or on error, returns -1.
 */
int file_write(int fd, const void *buf, int buflen)
{
    int write_len;

    if ((write_len = write(fd, buf, buflen)) == -1) {
        syserror(0, 0, 0, "Write failed");
        return -1;
    }
    if (write_len != buflen) {
        log0(0,0,0,"Write error: wrote %d bytes, expected %d",write_len,buflen);
        return -1;
    }
    return write_len;
}

/**
 * Returns the free disk space in bytes of the filesystem that contains
 * the given file.  Returns 2^63-1 on error.
 */
int64_t free_space(const char *file)
{
#ifdef WINDOWS
    ULARGE_INTEGER bytes_free;
    char *dirname, *filename;

    split_path(file, &dirname, &filename);
    if (dirname == NULL) {
        free(dirname);
        free(filename);
        return 0x7FFFFFFFFFFFFFFFULL;
    }
    if (!GetDiskFreeSpaceEx(dirname, &bytes_free, NULL, NULL)) {
        char errbuf[300];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
                GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
        log0(0, 0, 0, "Error in GetDiskFreeSpaceEx: %s", errbuf);
        free(dirname);
        free(filename);
        return 0x7FFFFFFFFFFFFFFFULL;
    } else {
        log3(0, 0, 0, "Free space: %s", printll(bytes_free.QuadPart));
        free(dirname);
        free(filename);
        return bytes_free.QuadPart;
    }
#else
    struct statvfs buf;

    if (statvfs(file, &buf) == -1) {
        syserror(0, 0, 0, "statvfs failed");
        return 0x7FFFFFFFFFFFFFFFULL;
    } else {
        log3(0, 0, 0, "Free space: %s",
                      printll((uint64_t)buf.f_bsize * buf.f_bavail));
        return (int64_t)buf.f_bsize * buf.f_bavail;
    }
#endif
}

/**
 * Determines if the priority value passed in is valid.
 * Returns 1 on success, 0 on fail
 */
int valid_priority(int priority)
{
#ifdef WINDOWS
    if ((priority >= -2) && (priority <= 2)) {
        return 1;
    } else {
        return 0;
    }
#else
    if ((priority >= -20) && (priority <= 19)) {
        return 1;
    } else {
        return 0;
    }
#endif
}

/**
 * Returns a 32-bit random number.
 * Some implementations of rand() generate values from 0 to 32767,
 * so this guarantees we get a full 32 bits.
 */
uint32_t rand32()
{
    return((rand() & 0x7FFF) << 17) | ((rand() & 0x7FFF) << 2) | (rand() & 0x2);
}

/**
 * Safe malloc routine that always returns non-NULL
 * On error, exit()
 */
void *safe_malloc(size_t size)
{
    void *p = malloc(size);
    if (p == NULL) {
        syserror(0, 0, 0, "malloc failed!");
        exit(ERR_ALLOC);
    }
    return p;
}

/**
 * Safe calloc routine that always returns non-NULL
 * On error, exit()
 */
void *safe_calloc(size_t num, size_t size)
{
    void *p = calloc(num, size);
    if (p == NULL) {
        syserror(0, 0, 0, "calloc failed!");
        exit(ERR_ALLOC);
    }
    return p;
}

#define RTT_MIN 1.0e-6
#define RTT_MAX 1000.0

/**
 * Convert grtt from a double to a single byte.
 * As defined in RFC 5401
 */
uint8_t quantize_grtt(double rtt)
{
    if (rtt > RTT_MAX) {
        rtt = RTT_MAX;
    } else if (rtt < RTT_MIN) {
        rtt = RTT_MIN;
    }
    if (rtt < (33.0 * RTT_MIN)) {
        return ((uint8_t)(rtt / RTT_MIN) - 1);
    } else {
        return ((uint8_t)(0 + ceil(255.0 - (13.0 * log(RTT_MAX/rtt)))));
    }
}

/**
 * Convert grtt from a single byte to a double
 * As defined in RFC 5401
 */
double unquantize_grtt(uint8_t rtt)
{
    return ((rtt <= 31) ?
            (((double)(rtt + 1)) * (double)RTT_MIN) :
            (RTT_MAX / exp(((double)(255 - rtt)) / (double)13.0)));
}

/**
 * Convert the group size from an int to an 8-bit float (5 bit M, 3 bit E)
 */
uint8_t quantize_gsize(int size)
{
    double M;
    int E;
    int rval;

    M = size;
    E = 0;
    while (M >= 10) {
        M /= 10;
        E++;
    }
    rval = ((int)((M * 32.0 / 10.0) + 0.5)) << 3;
    if (rval > 0xFF) {
        M /= 10;
        E++;
        rval = ((int)((M * 32.0 / 10.0) + 0.5)) << 3;
    }
    rval |= E;
    
    return rval;
}

/**
 * Convert the group size from an 8-bit float to an int (5 bit M, 3 bit E)
 */
int unquantize_gsize(uint8_t size)
{
    int E, i;
    double rval;

    E = size & 0x7;
    rval = (size >> 3) * (10.0 / 32.0);
    for (i = 0; i < E; i++) {
        rval *= 10;
    }

    return (int)(rval + 0.5);
}

/**
 * Convert rate from an int to a 16-bit float
 * As defined in RFC 5740
 */
uint16_t quantize_rate(uint32_t rate)
{
    int E;
    double M;
    int rval;

    M = rate;
    E = 0;
    while (M > 10) {
        M /= 10;
        E++;
    }
    rval = (((int)(M * 4096.0 / 10.0 + 0.5)) << 4);
    if (rval > 0xFFFF) {
        M /= 10;
        E++;
        rval = (((int)(M * 4096.0 / 10.0 + 0.5)) << 4);
    }
    rval |= E;
    
    return rval;
}

/**
 * Convert rate in B/s from a 16-bit float to an int
 * As defined in RFC 5740
 */
uint32_t unquantize_rate(uint16_t rate)
{
    int E, i;
    double rval;

    E = rate & 0xF;
    rval = (rate >> 4) * (10.0 / 4096.0);
    for (i = 0; i < E; i++) {
        rval *= 10;
    }

    // For now, cap at max uint32 (~4.2GB/s)
    return (uint32_t)(rval > 0xFFFFFFFF ? 0xFFFFFFFF : rval);
}

