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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <io.h>

#else  // if WINDOWS

#include <unistd.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#endif

#include "server.h"
#include "server_send.h"
#include "server_phase.h"
#include "server_common.h"

/**
 * Checks to see if a file/directory is in the exclude list
 */
int file_excluded(const char *filename)
{
    int found, i;

    for (found = 0, i = 0; (i < excludecount) && !found; i++) {
        if (!strcmp(filename, exclude[i])) {
            found = 1;
        }
    }

    return found;
}

/**
 * Performs the send for a particular file/directory.  If a directory is
 * specified, get the list of files and call recursively for each.
 * Returns non-zero if a file was sent and none received it, 0 otherwise
 */
int send_file(const char *f_basedir, const char *filename,
              const char *n_destfname, uint32_t group_id, uint8_t group_inst,
              int delete, int freespace)
{
    static uint16_t file_id = 1;
    struct finfo_t finfo;
    stat_struct statbuf;
    char path[MAXPATHNAME], destpath[MAXPATHNAME];
    int len, rval, fd, emptydir, maxsecsize;

    log2(group_id, 0, 0, "----- %s -----", filename);
    len = snprintf(path, sizeof(path), "%s%c%s", f_basedir, PATH_SEP, filename);
    if ((len >= sizeof(path)) || (len == -1)) {
        log1(group_id, 0, 0, "Max pathname length exceeded: %s%c%s",
                    f_basedir, PATH_SEP, filename);
        return ERR_NONE;
    }
    if (!delete && !freespace) {
        if (follow_links) {
            rval = stat_func(path, &statbuf);
        } else {
            rval = lstat_func(path, &statbuf);
        }
        if (rval == -1) {
            syserror(group_id,0,0,"Error getting file status for %s", filename);
            return ERR_NONE;
        }
    }
    if (file_excluded(filename)) {
        log2(group_id, 0, 0, "Skipping %s", filename);
        return ERR_NONE;
    }
    rval = ERR_NONE;
    if (freespace) {
        memset(&finfo, 0, sizeof(struct finfo_t));
        finfo.ftype = FTYPE_FREESPACE;
        finfo.basedir = f_basedir;
        finfo.filename = n_destfname;
        finfo.destfname = n_destfname;
        finfo.group_id = group_id;
        finfo.group_inst = group_inst;
        finfo.file_id = file_id++;
        if (file_id == 0) {
            file_id = 1;
        }
        finfo.deststate = safe_calloc(destcount ? destcount : MAXDEST,
                sizeof(struct deststate_t));

        rval = announce_phase(&finfo);
        if (rval == ERR_NONE) {
            rval = transfer_phase(&finfo);
        }
        free(finfo.deststate);
    } else if (delete) {
        memset(&finfo, 0, sizeof(struct finfo_t));
        finfo.ftype = FTYPE_DELETE;
        finfo.basedir = f_basedir;
        finfo.filename = filename;
        finfo.destfname = n_destfname;
        finfo.group_id = group_id;
        finfo.group_inst = group_inst;
        finfo.file_id = file_id++;
        if (file_id == 0) {
            file_id = 1;
        }

        finfo.deststate = safe_calloc(destcount ? destcount : MAXDEST,
                sizeof(struct deststate_t));
        rval = announce_phase(&finfo);
        if (rval == ERR_NONE) {
            rval = transfer_phase(&finfo);
        }
        free(finfo.deststate);
    } else if (S_ISREG(statbuf.st_mode)) {
        if ((fd = open(path, OPENREAD, 0)) == -1) {
            syserror(group_id, 0, 0, "Error reading file %s", filename);
            return ERR_NONE;
        }
        close(fd);
        memset(&finfo, 0, sizeof(struct finfo_t));
        finfo.ftype = FTYPE_REG;
        finfo.basedir = f_basedir;
        finfo.filename = filename;
        finfo.destfname = n_destfname;
        finfo.group_id = group_id;
        finfo.group_inst = group_inst;
        finfo.file_id = file_id++;
        if (file_id == 0) {
            file_id = 1;
        }
        finfo.size = statbuf.st_size;
        finfo.tstamp = statbuf.st_mtime;

        maxsecsize = (blocksize * 8 > MAXSECTION ? MAXSECTION : blocksize * 8);
        if (finfo.size) {
            finfo.blocks = (int32_t)((finfo.size / blocksize) +
                    (finfo.size % blocksize ? 1 : 0));
            finfo.sections = (finfo.blocks / maxsecsize) +
                    (finfo.blocks % maxsecsize ? 1 : 0);
            finfo.secsize_small = finfo.blocks / finfo.sections;
            finfo.secsize_big = finfo.secsize_small +
                    (finfo.blocks % finfo.sections ? 1 : 0);
            finfo.big_sections =
                    finfo.blocks - (finfo.secsize_small * finfo.sections);
        } else {
            finfo.blocks = 0;
            finfo.sections = 0;
            finfo.secsize_small = 0;
            finfo.secsize_big = 0;
            finfo.big_sections = 0;
        }

        finfo.naklist = safe_calloc(finfo.blocks, 1);
        finfo.deststate = safe_calloc(destcount ? destcount : MAXDEST,
                sizeof(struct deststate_t));
        finfo.partial = 1;
        rval = announce_phase(&finfo);
        if (rval == ERR_NONE) {
            rval = transfer_phase(&finfo);
        }
        free(finfo.deststate);
        free(finfo.naklist);
#ifndef WINDOWS
    } else if (S_ISLNK(statbuf.st_mode)) {
        char linkname[MAXPATHNAME];

        memset(linkname, 0, sizeof(linkname));
        if (readlink(path, linkname, sizeof(linkname)-1) == -1) {
            syserror(group_id, 0, 0, "Failed to read symbolic link %s", path);
            return ERR_NONE;
        }
        // Both the file name and the link have to fit into a fileinfo_h.name
        if (strlen(linkname) + strlen(filename) + 2 > MAXPATHNAME) {
            log0(group_id, 0, 0, "Combined file name %s and link %s too long",
                        filename, linkname);
            return ERR_NONE;
        }
        memset(&finfo, 0, sizeof(struct finfo_t));
        finfo.ftype = FTYPE_LINK;
        finfo.basedir = f_basedir;
        finfo.filename = filename;
        finfo.destfname = n_destfname;
        finfo.linkname = linkname;
        finfo.group_id = group_id;
        finfo.group_inst = group_inst;
        finfo.file_id = file_id++;
        if (file_id == 0) {
            file_id = 1;
        }
        finfo.deststate = safe_calloc(destcount ? destcount : MAXDEST,
                sizeof(struct deststate_t));
        finfo.partial = 1;
        rval = announce_phase(&finfo);
        if (rval == ERR_NONE) {
            rval = transfer_phase(&finfo);
        }
        free(finfo.deststate);
#endif
    } else if (S_ISDIR(statbuf.st_mode)) {
        // read directory and do recursive send
#ifdef WINDOWS
        intptr_t ffhandle;
        struct _finddatai64_t ffinfo;
        char dirglob[MAXPATHNAME];

        snprintf(dirglob, sizeof(dirglob), "%s%c%s%c*", f_basedir, PATH_SEP,
                                                        filename, PATH_SEP);
        if ((ffhandle = _findfirsti64(dirglob, &ffinfo)) == -1) {
            syserror(group_id, 0, 0, "Failed to open directory %s%c%s",
                        f_basedir, PATH_SEP, filename);
            return ERR_NONE;
        }
        emptydir = 1;
        do {
            len = snprintf(path, sizeof(path), "%s/%s", filename, ffinfo.name);
            log3(group_id, 0, 0, "Checking file %s", path);
            if ((len >= sizeof(path)) || (len == -1)) {
                log0(group_id, 0, 0, "Max pathname length exceeded: %s/%s",
                            filename, ffinfo.name);
                continue;
            }
            len = snprintf(destpath, sizeof(destpath), "%s/%s",
                           n_destfname, ffinfo.name);
            if ((len >= sizeof(destpath)) || (len == -1)) {
                log0(group_id, 0, 0, "Max pathname length exceeded: %s/%s",
                            n_destfname, ffinfo.name);
                continue;
            }
            if (strcmp(ffinfo.name, ".") && strcmp(ffinfo.name, "..")) {
                emptydir = 0;
                rval = send_file(f_basedir, path, destpath,
                                 group_id, group_inst, 0, 0);
                if (rval != ERR_NONE) {
                    break;
                }
            }
        } while (_findnexti64(ffhandle, &ffinfo) == 0);
        _findclose(ffhandle);
#else
        DIR *dir;
        struct dirent *de;
        char dirname[MAXPATHNAME];

        snprintf(dirname, sizeof(dirname), "%s%c%s", f_basedir, PATH_SEP,
                 filename);
        if ((dir = opendir(dirname)) == NULL) {
            syserror(group_id, 0, 0, "Failed to open directory %s", dirname);
            return ERR_NONE;
        }
        // errno needs to be set to 0 before calling readdir, otherwise
        // we'll report a false error when we exhaust the directory
        emptydir = 1;
        while ((errno = 0, de = readdir(dir)) != NULL) {
            len = snprintf(path, sizeof(path), "%s/%s", filename, de->d_name);
            if ((len >= sizeof(path)) || (len == -1)) {
                log0(group_id, 0, 0, "Max pathname length exceeded: %s/%s",
                            filename, de->d_name);
                continue;
            }
            len = snprintf(destpath, sizeof(destpath), "%s/%s",
                           n_destfname, de->d_name);
            if ((len >= sizeof(destpath)) || (len == -1)) {
                log0(group_id, 0, 0, "Max pathname length exceeded: %s/%s",
                            n_destfname, de->d_name);
                continue;
            }
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
                emptydir = 0;
                rval = send_file(f_basedir, path, destpath,
                                 group_id, group_inst, 0, 0);
                if (rval != ERR_NONE) {
                    break;
                }
            }
        }
        if (errno && (errno != ENOENT)) {
            syserror(group_id, 0, 0, "Failed to read directory %s", filename);
        }
        closedir(dir);
#endif
        if (emptydir) {
            memset(&finfo, 0, sizeof(struct finfo_t));
            finfo.ftype = FTYPE_DIR;
            finfo.basedir = f_basedir;
            finfo.filename = filename;
            finfo.destfname = n_destfname;
            finfo.group_id = group_id;
            finfo.group_inst = group_inst;
            finfo.file_id = file_id++;
            if (file_id == 0) {
                file_id = 1;
            }
            finfo.deststate = safe_calloc(destcount ? destcount : MAXDEST,
                    sizeof(struct deststate_t));
            finfo.partial = 1;
            rval = announce_phase(&finfo);
            if (rval == ERR_NONE) {
                rval = transfer_phase(&finfo);
            }
            free(finfo.deststate);
        }
    } else {
        log2(group_id, 0, 0, "Skipping special file %s", filename);
    }
    return rval;
}

/**
 * Write a restart file entry for a particular client.
 * Returns 1 on success, o on fail.
 */
int write_restart_host(uint32_t group_id, int fd, int i)
{
    struct server_restart_host_t host;

    memset(&host, 0, sizeof(host));
    strncpy(host.name, destlist[i].name, sizeof(host.name));
    host.name[sizeof(host.name)-1] = '\x0';
    host.id = destlist[i].id;
    if (destlist[i].has_fingerprint) {
        host.has_fingerprint = 1;
        memcpy(host.keyfingerprint, destlist[i].keyfingerprint,
               HMAC_LEN);
    }
    host.is_proxy = destlist[i].isproxy;
    if (file_write(fd, &host, sizeof(host)) == -1) {
        log0(group_id, 0, 0, "Failed to write host for restart file");
        return 0;
    }
    return 1;
}

/**
 * Save the state of a failed transfer so it can restarted later.
 */
void write_restart_file(uint32_t group_id, uint8_t group_inst)
{
    struct server_restart_t header;
    char restart_name[MAXFILENAME];
    char proxy_listed[MAXPROXYDEST];
    int fd, opened, i, j, proxycnt, found;

    memset(proxy_listed, 0, sizeof(proxy_listed));
    opened = 0;
    proxycnt = 0;
    for (i = 0; i < destcount; i++) {
        if ((!destlist[i].isproxy) && client_error(i)) {
            if (!opened) {
                snprintf(restart_name, sizeof(restart_name),
                         "_group_%08X_restart", group_id);
                if ((fd = open(restart_name, OPENWRITE | O_CREAT | O_TRUNC,
                               0644)) == -1) {
                    syserror(group_id, group_inst, 0,
                             "Failed to create restart file");
                    return;
                }

                // Write header
                header.group_id = group_id;
                header.group_inst = group_inst;
                header.filecount = filecount;
                if (file_write(fd, &header, sizeof(header)) == -1) {
                    log0(group_id, group_inst, 0,
                            "Failed to write header for restart file");
                    goto errexit;
                }

                // Write file list
                for (j = 0; j < filecount; j++) {
                    if (file_write(fd, filelist[j],sizeof(filelist[j])) == -1) {
                        log0(group_id, group_inst, 0,
                                "Failed to write filename for restart file");
                        goto errexit;
                    }
                }
                opened = 1;
            }
            if (!write_restart_host(group_id, fd, i)) {
                goto errexit;
            }
            if (destlist[i].proxyidx != -1) {
                for (j = 0, found = 0; (j < proxycnt) && !found; j++) {
                    if (proxy_listed[j] == destlist[i].proxyidx) {
                        found = 1;
                    }
                }
                if (!found) {
                    if (!write_restart_host(group_id, fd,
                                            destlist[i].proxyidx)) {
                        goto errexit;
                    }
                    proxy_listed[proxycnt++] = destlist[i].proxyidx;
                }
            }
        }
    }

    if (opened) {
        close(fd);
    }
    return;

errexit:
    close(fd);
    unlink(restart_name);
}

/**
 * The main sending function.  Goes through all files/directories specified on
 * the command line and initializes the group.
 */
int send_files(void)
{
    int i, j, rval, len, found_base, delete;
    struct finfo_t group_info;
    char *dir, *base;
    time_t t;
    int (*ncmp)(const char *, const char *, size_t);
    char path[MAXPATHNAME], l_destfname[MAXPATHNAME], mcast[INET6_ADDRSTRLEN];

#ifdef WINDOWS
    ncmp = strnicmp;
#else
    ncmp = strncmp;
#endif

    memset(&group_info, 0, sizeof(struct finfo_t));
    if (restart_groupid) {
        group_info.group_id = restart_groupid;
        group_info.group_inst = restart_groupinst + 1;
    } else {
        group_info.group_id = rand32();
        group_info.group_inst = 0;
    }
    group_info.deststate = safe_calloc(destcount ? destcount : MAXDEST,
                                  sizeof(struct deststate_t));
    
    t = time(NULL);
    if (!showtime) slog2("");
    log2(group_info.group_id, 0, 0, "%s", VERSIONSTR);
    if (!showtime) clog2(group_info.group_id, 0, 0, "Starting at %s",ctime(&t));
    if (privkey.key) {
        if ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) {
            log2(group_info.group_id, 0, 0,
                    "Loaded %d bit RSA key with fingerprint %s",
                       RSA_keylen(privkey.rsa) * 8,
                       print_key_fingerprint(privkey, KEYBLOB_RSA));
        } else {
            log2(group_info.group_id, 0, 0,
                    "Loaded ECDSA key with curve %s and fingerprint %s",
                       curve_name(get_EC_curve(privkey.ec)),
                       print_key_fingerprint(privkey, KEYBLOB_EC));
        }
    }
    if (dhkey.key) {
        log2(group_info.group_id, 0, 0, "Loaded ECDH key with curve %s",
                   curve_name(get_EC_curve(dhkey.ec)));
    }
    if (cc_type == CC_NONE || cc_type == CC_UFTP3) {
        if (rate == -1) {
            log2(group_info.group_id, 0, 0,
                    "Transfer rate: full interface speed");
        } else {
            log2(group_info.group_id, 0, 0, "Transfer rate: %d Kbps (%d KB/s)",
                       rate * 8 / 1024, rate / 1024);
            log2(group_info.group_id, 0, 0,
                    "Wait between packets: %d us", packet_wait);
        }
    } else if (cc_type == CC_TFMCC) {
        log2(group_info.group_id, 0, 0, "Transfer rate: dynamic via TFMCC");
    }

    if (log_level >= 2) {
        rval = getnameinfo((struct sockaddr *)&receive_dest,
                family_len(receive_dest), mcast, sizeof(mcast),
                NULL, 0, NI_NUMERICHOST);
        if (rval) {
            log2(group_info.group_id, 0, 0,
                    "getnameinfo failed: %s", gai_strerror(rval));
        }
        log2(group_info.group_id, 0, 0, "Using private multicast address %s  "
                "Group ID: %08X", mcast, group_info.group_id);
    }
    rval = announce_phase(&group_info);
    if (rval == ERR_NONE) {
        for (i = 0; i < filecount; i++) {
            if (!strcmp(filelist[i], "@FREESPACE")) {
                rval = send_file(".", ".", ".",
                        group_info.group_id, group_info.group_inst, 0, 1);
                if (rval != ERR_NONE) {
                    break;
                }
                continue;
            }
            if (!strncmp(filelist[i], "@DELETE:", 8)) {
                split_path(&filelist[i][8], &dir, &base);
                delete = 1;
            } else {
                split_path(filelist[i], &dir, &base);
                delete = 0;
            }
            if (basedircount > 0) {
                for (found_base = 0, j = 0; j < basedircount; j++) {
                    if (!ncmp(basedir[j],filelist[i], strlen(basedir[j]))) {
                        found_base = 1;
                        break;
                    }
                }
                if (!found_base) {
                    log1(group_info.group_id, 0, 0, "Skipping %s: "
                            "doesn't match any base", filelist[i]);
                    free(dir);
                    free(base);
                    continue;
                }
                strncpy(l_destfname, filelist[i] + strlen(basedir[j]),
                        sizeof(l_destfname)-1);
            } else {
                strncpy(l_destfname, base, sizeof(l_destfname)-1);
            }
#if PATH_SEP != '/'
            // Translate any PATH_SEP in the sent file name to '/'
            {
                char *p;
                while ((p = strchr(l_destfname, PATH_SEP)) != NULL) {
                    *p = '/';
                }
            }
#endif
            if (strcmp(destfname, "")) {
                if ((filecount > 1) || dest_is_dir) {
                    len = snprintf(path, sizeof(path), "%s/%s",
                                   destfname, l_destfname);
                    if ((len >= sizeof(path)) || (len == -1)) {
                        log0(group_info.group_id, 0, 0, "Max pathname length "
                                "exceeded: %s/%s", destfname, base);
                        free(dir);
                        free(base);
                        continue;
                    }
                    rval = send_file(dir, base, path, group_info.group_id,
                                     group_info.group_inst, delete, 0);
                } else {
                    rval = send_file(dir, base, destfname, group_info.group_id,
                                     group_info.group_inst, delete, 0);
                }
            } else {
                rval = send_file(dir, base, l_destfname, group_info.group_id,
                                 group_info.group_inst, delete, 0);
            }
            free(dir);
            free(base);
            if (rval != ERR_NONE) {
                break;
            }
        }
        if (rval == ERR_NONE) {
            if (files_sent == 0) {
                rval = ERR_NO_FILES;
            }
            log2(group_info.group_id, 0, 0, "-----------------------------");
            completion_phase(&group_info);
        }
    }
    if (save_fail) {
        write_restart_file(group_info.group_id, group_info.group_inst);
    }
    free(group_info.deststate);

    t = time(NULL);
    if (!showtime) clog2(group_info.group_id, 0, 0, "uftp: Finishing at %s",
                         ctime(&t));
    return rval;
}

