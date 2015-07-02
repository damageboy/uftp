/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2014   Dennis A. Bush, Jr.   bush@tcnj.edu
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
#include <errno.h>

#ifdef WINDOWS

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#endif

#include "client.h"
#include "client_config.h"

/**
 * Global command line values and sockets
 */
SOCKET listener;
char tempdir[MAXDIRNAME], destdir[MAXDIR][MAXDIRNAME];
char pidfile[MAXPATHNAME];
char keyfile[MAXLIST][MAXPATHNAME], keyinfo[MAXLIST][MAXPATHNAME];
char backupdir[MAXDIR][MAXDIRNAME];
char statusfilename[MAXPATHNAME];
FILE *status_file;
int debug, encrypted_only, dscp, destdircnt, tempfile, keyinfo_count;
int interface_count, pub_multi_count, keyfile_count, rcvbuf, backupcnt;
char postreceive[MAXPATHNAME], portname[PORTNAME_LEN];
int port, move_individual, cache_len, noname;
uint32_t uid;
union sockaddr_u hb_hosts[MAXLIST];
struct iflist m_interface[MAX_INTERFACES];
union sockaddr_u pub_multi[MAX_INTERFACES];
struct group_list_t group_list[MAXLIST];
struct fp_list_t server_keys[MAXLIST];
struct iflist ifl[MAX_INTERFACES];
struct timeval next_keyreq_time, next_hb_time;
int ifl_len, server_count, key_count, has_proxy, sys_keys, priority;
int hbhost_count, hb_interval;
union key_t privkey[MAXLIST];
int privkey_type[MAXLIST];
struct fp_list_t proxy_info;
union key_t proxy_pubkey, proxy_dhkey;
int proxy_pubkeytype;

extern char *optarg;
extern int optind;

/**
 * Adds a server and its fingerprint to the list of approved servers
 */
void add_server_by_name(const char *server, const char *ip,
                        const char *fingerprint)
{
    struct addrinfo ai_hints, *ai_rval;
    uint32_t server_uid;
    int rval;

    server_uid = strtoul(server, NULL, 16);
    if ((server_uid == 0xffffffff) || (server_uid == 0)) {
        fprintf(stderr, "Invalid server UID %s\n", server);
        exit(ERR_PARAM);
    }

    memset(&ai_hints, 0, sizeof(ai_hints));
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_DGRAM;
    ai_hints.ai_protocol = 0;
    ai_hints.ai_flags = 0;
    if ((rval = getaddrinfo(ip, NULL, &ai_hints, &ai_rval)) != 0) {
        fprintf(stderr, "Invalid server name/address %s: %s\n",
                ip, gai_strerror(rval));
        exit(ERR_PARAM);
    }

    server_keys[server_count].uid = htonl(server_uid);
    memcpy(&server_keys[server_count].addr, ai_rval->ai_addr,
            ai_rval->ai_addrlen);
    server_keys[server_count].has_fingerprint =
            parse_fingerprint(server_keys[server_count].fingerprint,
                              fingerprint);
    server_count++;
    freeaddrinfo(ai_rval);
}

/**
 * Set defaults for all command line arguments
 */
void set_defaults(void)
{
    debug = 0;
    log_level = DEF_LOG_LEVEL;
    encrypted_only = 0;
    uid = 0;
    dscp = DEF_DSCP;
    strncpy(logfile, DEF_LOGFILE, sizeof(logfile)-1);
    logfile[sizeof(logfile)-1] = '\x0';
    strncpy(statusfilename, "", sizeof(statusfilename)-1);
    statusfilename[sizeof(statusfilename)-1] = '\x0';
    status_file = NULL;
    noname = 0;
    memset(pidfile, 0, sizeof(pidfile));
    interface_count = 0;
    strncpy(portname, DEF_PORT, sizeof(portname)-1);
    portname[sizeof(portname)-1] = '\x0';
    port = atoi(portname);
    tempfile = 0;
    strncpy(tempdir, DEF_TEMPDIR, sizeof(tempdir)-1);
    tempdir[sizeof(tempdir)-1] = '\x0';
    destdircnt = 0;
    backupcnt = 0;
    pub_multi_count = 0;
    key_count = 0;
    keyfile_count = 0;
    keyinfo_count = 0;
    rcvbuf = 0;
    server_count = 0;
    has_proxy = 0;
    sys_keys = 0;
    memset(hb_hosts, 0, sizeof(hb_hosts));
    hbhost_count = 0;
    hb_interval = DEF_HB_INT;
    priority = 0;
    memset(postreceive, 0, sizeof(postreceive));
    move_individual = 0;
    max_log_size = 0;
    max_log_count = DEF_MAX_LOG_COUNT;
    cache_len = DEF_CACHE;
}

/**
 * Set argument defaults, read and validate command line options
 */
void process_args(int argc, char *argv[])
{
    int c, i, listidx, rval;
    long tmpval;
    struct addrinfo ai_hints, *ai_rval;
    char line[1000], *servername, *ipstr, *fingerprint;
    char *p, *p2, *hoststr, *portstr, pubname[INET6_ADDRSTRLEN];
    FILE *serverfile;
    const char opts[]="dx:qF:L:P:s:c:I:p:tT:D:A:M:B:Q:EU:S:R:k:K:mN:ig:n:h:H:";

    set_defaults();

    // read lettered arguments
    while ((c = getopt(argc, argv, opts)) != EOF) {
        switch (c) {
        case 'd':
            debug = 1;
            break;
        case 'x':
            log_level = atoi(optarg);
            if (log_level < 0) {
                fprintf(stderr, "Invalid log level\n");
                exit(ERR_PARAM);
            }
            break;
        case 'q':
            noname = 1;
            break;
        case 'F':
            strncpy(statusfilename, optarg, sizeof(statusfilename)-1);
            statusfilename[sizeof(statusfilename)-1] = '\x0';
            break;
        case 'L':
            strncpy(logfile, optarg, sizeof(logfile)-1);
            logfile[sizeof(logfile)-1] = '\x0';
            break;
        case 'P':
            strncpy(pidfile, optarg, sizeof(pidfile)-1);
            pidfile[sizeof(pidfile)-1] = '\x0';
            break;
        case 's':
            strncpy(postreceive, optarg, sizeof(postreceive)-1);
            postreceive[sizeof(postreceive)-1] = '\x0';
            break;
        case 'c':
            cache_len = atoi(optarg);
            if ((cache_len < 10240) || (cache_len > 20971520)) {
                fprintf(stderr, "Invalid cache size\n");
                exit(ERR_PARAM);
            }
            break;
        case 'I':
            p = strtok(optarg, ",");
            while (p != NULL) {
                if ((listidx = getifbyname(p, ifl, ifl_len)) != -1) {
                    m_interface[interface_count++] = ifl[listidx];
                    p = strtok(NULL, ",");
                    continue;
                }
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(p, NULL,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid name/address %s: %s\n",
                            p, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                if ((listidx = getifbyaddr((union sockaddr_u *)ai_rval->ai_addr,
                        ifl, ifl_len)) == -1) {
                    fprintf(stderr, "Interface %s not found\n", p);
                    exit(ERR_PARAM);
                }
                m_interface[interface_count++] = ifl[listidx];
                freeaddrinfo(ai_rval);
                p = strtok(NULL, ",");
            }
            break;
        case 'p':
            strncpy(portname, optarg, sizeof(portname)-1);
            portname[sizeof(portname)-1] = '\x0';
            port = atoi(portname);
            if (port == 0) {
                fprintf(stderr, "Invalid port\n");
                exit(ERR_PARAM);
            }
            break;
        case 't':
            tempfile = 1;
            break;
        case 'T':
            strncpy(tempdir, optarg, sizeof(tempdir)-1);
            tempdir[sizeof(tempdir)-1] = '\x0';
            break;
        case 'D':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(destdir[destdircnt], p, sizeof(destdir[destdircnt])-1);
                destdir[destdircnt][sizeof(destdir[destdircnt])-1] = '\x0';
                destdircnt++;
                p = strtok(NULL, ",");
            }
            break;
        case 'A':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(backupdir[backupcnt],p,sizeof(backupdir[backupcnt])-1);
                backupdir[backupcnt][sizeof(backupdir[backupcnt])-1] = '\x0';
                backupcnt++;
                p = strtok(NULL, ",");
            }
            break;
        case 'M':
            p = strtok(optarg, ",");
            while (p != NULL) {
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(p, NULL,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid multicast address %s: %s\n",
                            p, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                memcpy(&pub_multi[pub_multi_count], ai_rval->ai_addr,
                        ai_rval->ai_addrlen);
                pub_multi_count++;
                freeaddrinfo(ai_rval);
                p = strtok(NULL, ",");
            }
            break;
        case 'B':
            rcvbuf = atoi(optarg);
            if ((rcvbuf < 65536) || (rcvbuf > 104857600)) {
                fprintf(stderr, "Invalid buffer size\n");
                exit(ERR_PARAM);
            }
            break;
        case 'Q':
            tmpval = strtol(optarg, NULL, 0);
            if ((tmpval < 0) || (tmpval > 63)) {
                fprintf(stderr, "Invalid dscp\n");
                exit(ERR_PARAM);
            }
            dscp = (tmpval & 0xFF) << 2;
            break;
        case 'E':
            encrypted_only = 1;
            break;
        case 'U':
            errno = 0;
            uid = strtoul(optarg, NULL, 16);
            if (errno) {
                perror("Invalid UID\n");
                exit(ERR_PARAM);
            }
            uid = htonl(uid);
            break;
        case 'S':
            if ((serverfile = fopen(optarg, "r")) == NULL) {
                fprintf(stderr, "Couldn't open server list %s: %s\n",
                        optarg, strerror(errno));
                exit(ERR_PARAM);
            }
            while (fgets(line, sizeof(line), serverfile)) {
                while ((strlen(line) != 0) && ((line[strlen(line)-1] == '\r') ||
                       (line[strlen(line)-1] == '\n'))) {
                    line[strlen(line)-1] = '\x0';
                }
                if ((line[0] == '#') || (line[0] == '\x0')) {
                    continue;
                }
                servername = line;
                ipstr = strchr(servername, '|');
                if (ipstr) {
                    *ipstr = '\x0';
                    ipstr++;
                    fingerprint = strchr(ipstr, '|');
                    if (fingerprint) {
                        *fingerprint = '\x0';
                        fingerprint++;
                    }
                } else {
                    fingerprint = NULL;
                }
                if (strlen(servername) >= DESTNAME_LEN) {
                    fprintf(stderr, "Server list: name too long\n");
                    exit(ERR_PARAM);
                }
                add_server_by_name(servername, ipstr, fingerprint);
            }
            if (!feof(serverfile) && ferror(serverfile)) {
                perror("Failed to read from server list file");
                exit(ERR_PARAM);
            }
            fclose(serverfile);
            break;
        case 'R':
            strncpy(line, optarg, sizeof(line));
            line[sizeof(line)-1] = '\x0';
            servername = strtok(line, "/");
            if (!servername) {
                fprintf(stderr, "Invalid host name\n");
                exit(ERR_PARAM);
            }
            fingerprint = strtok(NULL, "/");
            memset(&ai_hints, 0, sizeof(ai_hints));
            ai_hints.ai_family = AF_UNSPEC;
            ai_hints.ai_socktype = SOCK_DGRAM;
            ai_hints.ai_protocol = 0;
            ai_hints.ai_flags = 0;
            if ((rval = getaddrinfo(servername, NULL,
                    &ai_hints, &ai_rval)) != 0) {
                fprintf(stderr, "Invalid proxy address %s: %s\n",
                        servername, gai_strerror(rval));
                exit(ERR_PARAM);
            }
            memcpy(&proxy_info.addr, ai_rval->ai_addr, ai_rval->ai_addrlen);
            proxy_info.has_fingerprint =
                    parse_fingerprint(proxy_info.fingerprint, fingerprint);
            has_proxy = 1;
            freeaddrinfo(ai_rval);
            break;
        case 'k':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(keyfile[keyfile_count], p, sizeof(keyfile[0])-1);
                keyfile[keyfile_count][sizeof(keyfile[0])-1] = '\x0';
                keyfile_count++;
                p = strtok(NULL, ",");
            }
            break;
        case 'K':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(keyinfo[keyinfo_count], p, sizeof(keyinfo[0])-1);
                keyinfo[keyinfo_count][sizeof(keyinfo[0])-1] = '\x0';
                keyinfo_count++;
                p = strtok(NULL, ",");
            }
            break;
        case 'm':
            sys_keys = 1;
            break;
        case 'N':
            priority = atoi(optarg);
            if (!valid_priority(priority)) {
                fprintf(stderr, "Invalid priority value\n");
                exit(ERR_PARAM);
            }
            break;
        case 'i':
            move_individual = 1;
            break;
        case 'g':
            max_log_size = atoi(optarg);
            if ((max_log_size < 1) || (max_log_size > 1024)) {
                fprintf(stderr, "Invalid max log size\n");
                exit(ERR_PARAM);
            }
            max_log_size *= 1000000;
            break;
        case 'n':
            max_log_count = atoi(optarg);
            if ((max_log_count < 1) || (max_log_count > 1000)) {
                fprintf(stderr, "Invalid max log count\n");
                exit(ERR_PARAM);
            }
            break;
        case 'H':
            p = strtok(optarg, ",");
            while (p != NULL) {
                p2 = strchr(p, ':');
                if (p2) {
                    hoststr = strdup(p);
                    hoststr[p2 - p] = '\x0';
                    portstr = p2 + 1;
                } else {
                    hoststr = p;
                    portstr = NULL;
                }
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(hoststr, portstr,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid heartbeat address %s: %s\n",
                            p, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                memcpy(&hb_hosts[hbhost_count], ai_rval->ai_addr,
                        ai_rval->ai_addrlen);
                freeaddrinfo(ai_rval);
                if (portstr) {
                    free(hoststr);
                } else {
                    if (hb_hosts[hbhost_count].ss.ss_family == AF_INET6) {
                        hb_hosts[hbhost_count].sin6.sin6_port =
                                htons(atoi(DEF_PORT));
                    } else {
                        hb_hosts[hbhost_count].sin.sin_port =
                                htons(atoi(DEF_PORT));
                    }
                }
                hbhost_count++;
                p = strtok(NULL, ",");
            }
            break;
        case 'h':
            hb_interval = atoi(optarg);
            if ((hb_interval <= 0) || (hb_interval > 3600)) {
                fprintf(stderr, "Invalid heartbeat interval\n");
                exit(ERR_PARAM);
            }
            break;
        case '?':
            fprintf(stderr, USAGE);
            exit(ERR_PARAM);
        }
    }
    if (server_count) {
        for (i = 0; i < pub_multi_count; i++) {
            if (!is_multicast(&pub_multi[i], 1)) {
                if ((rval = getnameinfo((struct sockaddr *)&pub_multi[i],
                        family_len(pub_multi[i]), pubname, sizeof(pubname),
                        NULL, 0, NI_NUMERICHOST)) != 0) {
                    fprintf(stderr,"getnameinfo failed: %s",gai_strerror(rval));
                }
                fprintf(stderr, "Invalid source specific "
                        "multicast address: %s\n", pubname);
                exit(ERR_PARAM);
            }
        }
        if (pub_multi_count == 0) {
            fprintf(stderr, "Default multicast address %s invalid "
                    "for source specific multicast\n", DEF_PUB_MULTI);
            exit(ERR_PARAM);
        }
    }
    if ((keyfile_count != 0) && (keyinfo_count != 0) &&
            (keyfile_count != keyinfo_count)) {
        fprintf(stderr, "Must list same number of items for -k and -K\n");
        exit(ERR_PARAM);
    }
    if (has_proxy) {
        if (proxy_info.addr.ss.ss_family == AF_INET6) {
            proxy_info.addr.sin6.sin6_port = htons(port);
        } else {
            proxy_info.addr.sin.sin_port = htons(port);
        }
    }
    if (destdircnt == 0) {
        strncpy(destdir[0], DEF_DESTDIR, sizeof(destdir[0])-1);
        destdir[0][sizeof(destdir[0])-1] = '\x0';
        destdircnt++;
    }
    if ((backupcnt > 0) && (backupcnt != destdircnt)) {
        fprintf(stderr, "Must specify same number of backup directories "
                        "as destination directories\n");
        exit(ERR_PARAM);
    }
    if (tempfile && (strcmp(tempdir, ""))) {
        fprintf(stderr, "Cannot specify both -t and -T\n");
        exit(ERR_PARAM);
    }
}

