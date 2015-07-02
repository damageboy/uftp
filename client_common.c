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

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>

#ifdef WINDOWS

#include <ws2tcpip.h>
#include <io.h>
#include <direct.h>
#include <sys/utime.h>

#include "win_func.h"

#else  // if WINDOWS

#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <utime.h>

#endif

#include "client.h"
#include "client_common.h"

/**
 * Look for a given group in the global group list
 * Returns a pointer to the group in the list, or NULL if not found
 */
struct group_list_t *find_group(uint32_t group_id, uint8_t group_inst)
{
    int i;

    for (i = 0; i < MAXLIST; i++) {
        if ((group_list[i].group_id == group_id) &&
                (group_list[i].group_inst == group_inst)) {
            return &group_list[i];
        }
    }

    return NULL;
}

/**
 * Looks for the uid in a list of addresses.
 * Returns 1 if found, 0 if not found
 */
int uid_in_list(const uint32_t *addrlist, int size)
{
    int i;

    for (i = 0; i < size; i++) {
        if (addrlist[i] == 0) {
            return 0;
        }
        if (uid == addrlist[i]) {
            return 1;
        }
    }
    return 0;
}

/**
 * Reads in the contents of the restart file.
 */
void read_restart_file(struct group_list_t *group)
{
    struct client_restart_t *restart;
    char restart_name[MAXPATHNAME];
    int fd, i, rval;

    // Don't bother if we're not using a temp directory.
    if (!strcmp(tempdir, "")) {
        return;
    }

    // First abort any prior session with the same group_id.
    // This creates the restart file.
    for (i = 0; i < MAXLIST; i++) {
        if ((group_list[i].group_id == group->group_id) &&
                (group_list[i].group_inst < group->group_inst)) {
            file_cleanup(&group_list[i], 1);
        }
    }

    glog2(group, "Reading restart file");
    snprintf(restart_name, sizeof(restart_name), "%s%c_group_%08X_restart",
             tempdir, PATH_SEP, group->group_id);
    if ((fd = open(restart_name, OPENREAD, 0644)) == -1) {
        gsyserror(group, "Failed to read restart file");
        return;
    }

    // Read header
    restart = safe_calloc(sizeof(struct client_restart_t), 1);
    if ((rval = file_read(fd, restart, sizeof(struct client_restart_t),
                          0)) == -1) {
        glog0(group, "Failed to read header for restart file");
        goto err1;
    }
    if (rval != sizeof(struct client_restart_t)) {
        glog0(group, "Failed to read header for restart file "
                "(read %d, expected %d)", rval,sizeof(struct client_restart_t));
        goto err1;
    }

    // Read NAK list
    if (restart->blocks) {
        restart->naklist = safe_calloc(restart->blocks, 1);
        if (file_read(fd, restart->naklist, restart->blocks, 0) == -1) {
            glog0(group, "Failed to read NAK list for restart file");
            goto err2;
        }
    }

    // Read section_done list
    if (restart->sections) {
        restart->section_done = safe_calloc(restart->sections, 1);
        if (file_read(fd, restart->section_done, restart->sections, 0) == -1) {
            glog0(group, "Failed to read section_done list for restart file");
            goto err3;
        }
    }
    close(fd);
    unlink(restart_name);
    group->restartinfo = restart;
    glog3(group, "Reading restart file done");
    return;

err3:
    free(restart->section_done);
err2:
    free(restart->naklist);
err1:
    free(restart);
    close(fd);
}

/**
 * Save the state of a failed transfer so it can restarted later.
 */
void write_restart_file(struct group_list_t *group)
{
    struct file_t *fileinfo;
    struct client_restart_t restart;
    char restart_name[MAXPATHNAME];
    int fd;

    // Don't bother if we're not using a temp directory.
    if (!strcmp(tempdir, "")) {
        return;
    }

    glog2(group, "Writing restart file");
    memset(&restart, 0, sizeof(restart));
    fileinfo = &group->fileinfo;
    if (group->phase != PHASE_MIDGROUP) {
        restart.blocks = fileinfo->blocks;
        restart.sections = fileinfo->sections;
        restart.size = fileinfo->size;
        strncpy(restart.name, fileinfo->name, sizeof(restart.name));
        restart.name[sizeof(restart.name)-1] = '\x0';
    }

    snprintf(restart_name, sizeof(restart_name), "%s%c_group_%08X_restart",
             tempdir, PATH_SEP, group->group_id);
    if ((fd = open(restart_name, OPENWRITE | O_CREAT | O_TRUNC, 0644)) == -1) {
        gsyserror(group, "Failed to create restart file");
        return;
    }

    if (file_write(fd, &restart, sizeof(restart)) == -1) {
        glog0(group, "Failed to write header for restart file");
        goto errexit;
    }
    if (fileinfo->blocks && fileinfo->naklist) {
        if (file_write(fd, fileinfo->naklist, fileinfo->blocks) == -1) {
            glog0(group, "Failed to write NAK list for restart file");
            goto errexit;
        }
    }
    if (fileinfo->sections && fileinfo->section_done) {
        if (file_write(fd, fileinfo->section_done, fileinfo->sections) == -1) {
            glog0(group, "Failed to write section_done list for restart file");
            goto errexit;
        }
    }
    close(fd);
    return;

errexit:
    close(fd);
    unlink(restart_name);
}

/**
 * Checks to see if the multicast address used for the given group list member
 * is also being used by either another member or the public address list
 */
int other_mcast_users(struct group_list_t *group)
{
    int i;

    for (i = 0; i < pub_multi_count; i++) {
        if (!memcmp(&group->multi, &pub_multi[i], sizeof(union sockaddr_u))) {
            return 1;
        }
    }
    for (i = 0; i < MAXLIST; i++) {
        if ((&group_list[i] != group) && (!memcmp(&group->multi,
                &group_list[i].multi, sizeof(union sockaddr_u)))) {
            return 1;
        }
    }
    return 0;
}

/**
 * Run the postreceive script on list of received files
 */
void run_postreceive_multi(struct group_list_t *group, char *const *files,
                           int count)
{
    char **params;
    char gid_str[10];
    char gid_param[] = "-I";
    int i;

    if (!strcmp(postreceive, "")) {
        return;
    }

    params = safe_calloc(count + 4, sizeof(char *));

    snprintf(gid_str, sizeof(gid_str), "%08X", group->group_id);

    params[0] = postreceive;
    params[1] = gid_param;
    params[2] = gid_str;
    for (i = 0; i < count; i++) {
        params[i+3] = files[i];
    }
    params[count+4-1] = NULL;

    if (log_level >= 2) {
        cglog2(group, "Running postreceive: %s", postreceive);
        for (i = 1; i < count + 3; i++) {
            sclog2(" %s", params[i]);
        }
        slog2("");
    }

#ifdef WINDOWS
    {
        char cmdline[0x8000];  // Windows max command line length
        char cmdexe[MAXPATHNAME];
        int too_long, rval, is_cmd;

        strcpy(cmdline, "");
        if ((!strncmp(&postreceive[strlen(postreceive)-4], ".cmd", 4)) ||
                (!strncmp(&postreceive[strlen(postreceive)-4], ".bat", 4))) {
            is_cmd = 1;
            if (!GetEnvironmentVariable("SystemRoot", cmdexe, sizeof(cmdexe))) {
                char errbuf[300];
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                              0, errbuf, sizeof(errbuf), NULL);
                glog0(group, "Error getting sysroot: (%d) %s",
                             GetLastError(), errbuf);
                free(params);
                return;
            }
            strcat(cmdexe, "\\system32\\cmd.exe");
            strcat(cmdline, "/c \"");
        } else {
            is_cmd = 0;
        }
        for (too_long = 0, i = 0; i < count + 3; i++) {
            int size = 0x8000 - strlen(cmdline);
            if (size <= (int)strlen(params[i]) + 4) {
                too_long = 1;
                break;
            }
            // Quote everything except -I {group_id}
            if (i == 1 || i == 2) {
                strcat(cmdline, params[i]);
                strcat(cmdline," ");
            } else {
                strcat(cmdline, "\"");
                strcat(cmdline, params[i]);
                strcat(cmdline,"\" ");
            }
        }
        if (is_cmd) {
            strcat(cmdline, "\"");
        }

        if (!too_long) {
            STARTUPINFO startup_info;
            PROCESS_INFORMATION proc_info;

            GetStartupInfo(&startup_info);
            rval = CreateProcess(is_cmd ? cmdexe : postreceive, cmdline,
                NULL, NULL, 0, CREATE_NO_WINDOW, NULL, NULL,
                &startup_info, &proc_info);
            if (!rval) {
                char errbuf[300];
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                              0, errbuf, sizeof(errbuf), NULL);
                glog0(group, "Error running script: (%d) %s",
                             GetLastError(), errbuf);
            }
        }
    }
#else
    {
        pid_t pid;
        if ((pid = fork()) == -1) {
            gsyserror(group, "fork failed");
        } else if (pid == 0) {
            close(listener);
            close(1);
            close(2);
            execv(postreceive, params);
            gsyserror(group, "exec failed");
            exit(1);
        }
    }
#endif

    free(params);
}

/**
 * Run the postreceive script on a received file
 */
void run_postreceive(struct group_list_t *group, char *file)
{
    char *files[] = { file };
    run_postreceive_multi(group, files, 1);
}

/**
 * Clean up a group list entry.  Close the file if open,
 * free malloc'ed structures, drop the multicast group
 * (if no one else is using it) and free the slot.
 */
void file_cleanup(struct group_list_t *group, int abort_session)
{
    if (group->fileinfo.fd >= 0) {
        glog2(group, "starting file close");
        close(group->fileinfo.fd);
        glog2(group, "done file close");
        group->fileinfo.fd = -1;
        if (abort_session && !strcmp(tempdir, "")) {
            if (tempfile) {
                unlink(group->fileinfo.temppath);
            } else {
                unlink(group->fileinfo.filepath);
            }
        } else {
            if (tempfile) {
                move_to_backup(group);
                if (rename(group->fileinfo.temppath,
                           group->fileinfo.filepath) == -1) {
                    gsyserror(group, "Couldn't rename from %s to %s",
                             group->fileinfo.temppath,group->fileinfo.filepath);
                }
            }
            if (group->fileinfo.tstamp) {
                utim_buf utbuf;
                utbuf.actime = group->fileinfo.tstamp;
                utbuf.modtime = group->fileinfo.tstamp;
                if (utime(group->fileinfo.filepath, &utbuf) == -1) {
                    gsyserror(group, "utime failed");
                }
            }
        }
    }

    if (abort_session || (group->file_id == 0)) {
        if (!addr_blank(&group->multi) && !other_mcast_users(group) &&
                group->multi_join) {
            if (server_count > 0) {
                multicast_leave(listener, group->group_id, &group->multi,
                        m_interface, interface_count, server_keys,server_count);
                if (has_proxy) {
                    multicast_leave(listener, group->group_id, &group->multi,
                            m_interface, interface_count, &proxy_info, 1);
                }
            } else {
                multicast_leave(listener, group->group_id, &group->multi,
                        m_interface, interface_count, NULL, 0);
            }
        }
        if (group->server_pubkey.key) {
            if (group->keyextype == KEYEX_ECDH_ECDSA) {
                free_EC_key(group->server_pubkey.ec);
            } else {
                free_RSA_key(group->server_pubkey.rsa);
            }
        }
        if (group->server_dhkey.key) {
            free_EC_key(group->server_dhkey.ec);
            free_EC_key(group->client_dhkey.ec);
        }
        if (group->restartinfo &&
                (strcmp(group->restartinfo->name, ""))) {
            // We have unused restart info from the last run.
            // Chalk this up as a loss and delete the data file
            char filepath[MAXPATHNAME];
            snprintf(filepath, sizeof(filepath), "%s%c_group_%08X%c%s", tempdir,
                     PATH_SEP, group->group_id, PATH_SEP,
                     group->restartinfo->name);
            unlink(filepath);
        }
        if (abort_session) {
            write_restart_file(group);
        }

        free(group->loss_history);
        free(group->fileinfo.naklist);
        free(group->fileinfo.section_done);
        free(group->fileinfo.cache);
        free(group->fileinfo.cache_status);
        if (group->restartinfo) {
            free(group->restartinfo->naklist);
            free(group->restartinfo->section_done);
            free(group->restartinfo);
        }
        memset(group, 0, sizeof(struct group_list_t));
    } else {
        // Don't clear the file_id in case we need to respond to late DONEs
        if (!strcmp(tempdir, "")) {
            run_postreceive(group, group->fileinfo.filepath);
        }
        group->phase = PHASE_MIDGROUP;
        set_timeout(group, 0);
        free(group->fileinfo.naklist);
        free(group->fileinfo.section_done);
        free(group->fileinfo.cache);
        free(group->fileinfo.cache_status);
        group->fileinfo.naklist = NULL;
        group->fileinfo.section_done = NULL;
        group->fileinfo.cache = NULL;
        group->fileinfo.cache_status = NULL;
    }
}

/**
 * Flushes the cache to disk
 * Returns 1 on success, 0 on failure
 */
int flush_disk_cache(struct group_list_t *group)
{
    f_offset_t offset, seek_rval;
    int wrote_len;
    uint32_t i;

    if (group->fileinfo.cache_len == 0) return 1;
    offset = (f_offset_t) group->fileinfo.cache_start * group->blocksize;
    if ((seek_rval = lseek_func(group->fileinfo.fd,
            offset - group->fileinfo.curr_offset, SEEK_CUR)) == -1) {
        gsyserror(group, "lseek failed for file");
    }
    if (seek_rval != offset) {
        glog2(group, "offset is %s", printll(seek_rval));
        glog2(group, "  should be %s", printll(offset));
        if ((seek_rval = lseek_func(group->fileinfo.fd, offset,
                                    SEEK_SET)) == -1) {
            gsyserror(group, "lseek failed for file");
            return 0;
        }
    }
    if ((wrote_len = write(group->fileinfo.fd, group->fileinfo.cache,
                           group->fileinfo.cache_len)) == -1) {
        gsyserror(group, "Write failed for blocks %d - %d",
                        group->fileinfo.cache_start, group->fileinfo.cache_end);
        return 0;
    } else {
        group->fileinfo.curr_offset = offset + wrote_len;
        if (wrote_len != group->fileinfo.cache_len) {
            glog0(group, "Write failed for blocks %d - %d, only wrote %d bytes",
                        group->fileinfo.cache_start, group->fileinfo.cache_end);
            return 0;
        } else {
            glog4(group, "Wrote blocks %d - %d to disk from cache",
                        group->fileinfo.cache_start, group->fileinfo.cache_end);
            for (i = group->fileinfo.cache_start;
                    i <= group->fileinfo.cache_end; i++) {
                int status_idx = i - group->fileinfo.cache_start;
                if (group->fileinfo.cache_status[status_idx]) {
                    group->fileinfo.naklist[i] = 0;
                }
            }
            group->fileinfo.cache_start = group->fileinfo.cache_end + 1;
            while ((group->fileinfo.cache_start < group->fileinfo.blocks) &&
                    (!group->fileinfo.naklist[group->fileinfo.cache_start])) {
                group->fileinfo.cache_start++;
            }
            group->fileinfo.cache_end = group->fileinfo.cache_start;
            group->fileinfo.cache_len = 0;
            memset(group->fileinfo.cache, 0, cache_len);
            memset(group->fileinfo.cache_status,0,cache_len / group->blocksize);
            return 1;
        }
    }
}

/**
 * Initializes the uftp header of an outgoing packet
 */
void set_uftp_header(struct uftp_h *header, int func,
                     struct group_list_t *group)
{
    header->version = group->version;
    header->func = func;
    header->seq = htons(group->send_seq++);
    header->group_id = htonl(group->group_id);
    header->group_inst = group->group_inst;
    header->src_id = uid;
}       


/**
 * Sets the timeout time for a given group list member
 */
void set_timeout(struct group_list_t *group, int rescale)
{
    if (!rescale) {
        gettimeofday(&group->start_timeout_time, NULL);
    }
    group->timeout_time = group->start_timeout_time;
    switch (group->phase) {
    case PHASE_REGISTERED:
        add_timeval_d(&group->timeout_time, 4 * group->grtt);
        break;
    case PHASE_RECEIVING:
    case PHASE_MIDGROUP:
        if (group->robust * group->grtt < 1.0) {
            add_timeval_d(&group->timeout_time, 1.0);
        } else {
            add_timeval_d(&group->timeout_time, group->robust * group->grtt);
        }
        break;
    case PHASE_COMPLETE:
        add_timeval_d(&group->timeout_time, 4 * group->grtt);
        break;
    }
}

/**
 * Sends an ABORT message to a server
 */
void send_abort(struct group_list_t *group, const char *message)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct abort_h *abort_hdr;
    int payloadlen, enclen;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    abort_hdr = (struct abort_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, ABORT, group);
    abort_hdr->func = ABORT;
    abort_hdr->hlen = sizeof(struct abort_h) / 4;
    abort_hdr->host = 0;
    strncpy(abort_hdr->message, message, sizeof(abort_hdr->message) - 1);

    payloadlen = sizeof(struct abort_h);
    if ((group->phase != PHASE_REGISTERED) &&
            (group->keytype != KEY_NONE)) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
                group->keytype, group->groupkey, group->groupsalt,&group->ivctr,
                group->ivlen, group->hashtype, group->grouphmackey,
                group->hmaclen, group->sigtype, group->keyextype,
                group->client_privkey, group->client_privkeylen)) {
            glog0(group, "Error encrypting ABORT");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = enclen;
    } else {
        encrypted = NULL;
        outpacket = buf;
    }
    payloadlen += sizeof(struct uftp_h);

    if (nb_sendto(listener, outpacket, payloadlen, 0,
               (struct sockaddr *)&group->replyaddr,
               family_len(group->replyaddr)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending ABORT");
    }

    flush_disk_cache(group);
    file_cleanup(group, 1);
    free(buf);
    free(encrypted);
}

/**
 * Handles an ABORT message from a server
 */
void handle_abort(struct group_list_t *group, const unsigned char *message,
                  unsigned meslen)
{
    const struct abort_h *abort_hdr;
    int found;

    abort_hdr = (const struct abort_h *)message;
    if (meslen < (abort_hdr->hlen * 4U) ||
            ((abort_hdr->hlen * 4U) < sizeof(struct abort_h))) {
        glog1(group, "Rejecting ABORT from server: invalid message size");
        return;
    }

    found = 0;
    if (abort_hdr->host == 0) {
        if (((abort_hdr->flags & FLAG_CURRENT_FILE) != 0) &&
                (group->phase == PHASE_MIDGROUP)) {
            found = 0;
        } else {
            found = 1;
        }
    } else if (abort_hdr->host == uid) {
        found = 1;
    }

    if (found) {
        glog1(group, "Transfer aborted by server: %s", abort_hdr->message);
        flush_disk_cache(group);
        file_cleanup(group, 1);
    }
}

/**
 * Sends a KEY_REQ message to the proxy specified as the reply proxy
 */
void send_key_req()
{
    unsigned char *packet;
    struct uftp_h *header;
    struct key_req_h *keyreq;
    union sockaddr_u proxyaddr;
    char addrname[INET6_ADDRSTRLEN];
    int meslen, rval;

    packet = safe_calloc(sizeof(struct uftp_h) + sizeof(struct key_req_h), 1);

    header = (struct uftp_h *)packet;
    keyreq = (struct key_req_h *)(packet + sizeof(struct uftp_h));
    header->version = UFTP_VER_NUM;
    header->func = KEY_REQ;
    header->src_id = uid;
    keyreq->func = KEY_REQ;
    keyreq->hlen = sizeof(struct key_req_h) / 4;

    meslen = sizeof(struct uftp_h) + sizeof(struct key_req_h);
    proxyaddr = proxy_info.addr;
    if (nb_sendto(listener, packet, meslen, 0, 
                  (struct sockaddr *)&proxyaddr,
                  family_len(proxyaddr)) == SOCKET_ERROR) {
        sockerror(0, 0, 0, "Error sending KEY_REQ");
    } else {
        if ((rval = getnameinfo((struct sockaddr *)&proxyaddr,
                family_len(proxyaddr), addrname, sizeof(addrname),
                NULL, 0, NI_NUMERICHOST)) != 0) {
            log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
        }

        log2(0, 0, 0, "Sent KEY_REQ to %s:%s", addrname, portname);
    }

    free(packet);
    gettimeofday(&next_keyreq_time, NULL);
    next_keyreq_time.tv_sec += KEY_REQ_INT;
}

/**
 * Process a PROXY_KEY message
 */
void handle_proxy_key(const union sockaddr_u *src,
                      unsigned char *message, unsigned meslen)
{
    struct proxy_key_h *proxykey;
    unsigned char *keyblob, *dhblob, *sig;
    unsigned char fingerprint[HMAC_LEN];
    unsigned int fplen, keylen, dhlen, siglen;
    char addrname[INET6_ADDRSTRLEN];
    int rval;

    proxykey = (struct proxy_key_h *)message;

    if (meslen < (proxykey->hlen * 4U) ||
            ((proxykey->hlen * 4U) < sizeof(struct proxy_key_h) +
                ntohs(proxykey->bloblen) + ntohs(proxykey->dhlen) +
                ntohs(proxykey->siglen))) {
        log2(0, 0, 0, "Rejecting PROXY_KEY: invalid message size");
        return;
    }

    if ((rval = getnameinfo((const struct sockaddr *)src,
            family_len(*src), addrname, sizeof(addrname),
            NULL, 0, NI_NUMERICHOST)) != 0) {
        log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
    }
    log2(0, 0, 0, "Received PROXY_KEY from %s", addrname);

    if (!has_proxy) {
        log2(0, 0, 0, "No reply proxy specified");
        return;
    }
    if (!addr_equal(&proxy_info.addr, src)) {
        log2(0, 0, 0, "PROXY_KEY not from specified reply proxy");
        return;
    }

    keyblob = (unsigned char *)proxykey + sizeof(struct proxy_key_h);
    keylen = ntohs(proxykey->bloblen);
    dhblob = keyblob + keylen;
    dhlen = ntohs(proxykey->dhlen);
    sig = dhblob + dhlen;
    siglen = ntohs(proxykey->siglen);

    if (keyblob[0] == KEYBLOB_RSA) {
        if (!import_RSA_key(&proxy_pubkey.rsa, keyblob, keylen)) {
            log0(0, 0, 0, "Failed to import public key from PROXY_KEY");
            return;
        } 
        if (proxy_info.has_fingerprint) {
            hash(HASH_SHA1, keyblob, keylen, fingerprint, &fplen);
            if (memcmp(proxy_info.fingerprint, fingerprint, fplen)) {
                log1(0, 0, 0, "Failed to verify PROXY_KEY fingerprint");
                free_RSA_key(proxy_pubkey.rsa);
                return;
            }
        }
        if (!verify_RSA_sig(proxy_pubkey.rsa, HASH_SHA1,
                            (unsigned char *)&proxykey->nonce,
                            sizeof(proxykey->nonce), sig, siglen)) {
            log1(0, 0, 0, "Failed to verify PROXY_KEY signature");
            free_RSA_key(proxy_pubkey.rsa);
            return;
        }
    } else {
        if (!import_EC_key(&proxy_pubkey.ec, keyblob, keylen, 0)) {
            log0(0, 0, 0, "Failed to import public key from PROXY_KEY");
            return;
        } 
        if (proxy_info.has_fingerprint) {
            hash(HASH_SHA1, keyblob, keylen, fingerprint, &fplen);
            if (memcmp(proxy_info.fingerprint, fingerprint, fplen)) {
                log1(0, 0, 0, "Failed to verify PROXY_KEY fingerprint");
                free_RSA_key(proxy_pubkey.rsa);
                return;
            }
        }
        if (!verify_ECDSA_sig(proxy_pubkey.ec, HASH_SHA1,
                              (unsigned char *)&proxykey->nonce,
                              sizeof(proxykey->nonce), sig, siglen)) {
            log1(0, 0, 0, "Failed to verify PROXY_KEY signature");
            free_RSA_key(proxy_pubkey.rsa);
            return;
        }
    }
    if (dhlen) {
        if (!import_EC_key(&proxy_dhkey.ec, dhblob, dhlen, 1)) {
            log0(0, 0, 0, "Failed to import ECDH public key from PROXY_KEY");
            return;
        } 
    }
}

/**
 * Removes a full path from disk
 */
void clear_path(const char *path, struct group_list_t *group)
{
    stat_struct statbuf;
    char filename[MAXPATHNAME];
    int len;

    if (lstat_func(path, &statbuf) == -1) {
        if (errno != ENOENT) {
            gsyserror(group, "Error getting file status for %s", path);
        }
        return;
    }
    if (!S_ISDIR(statbuf.st_mode)) {
        unlink(path);
    } else {
#ifdef WINDOWS
        intptr_t ffhandle;
        struct _finddatai64_t finfo;
        char dirglob[MAXPATHNAME];

        snprintf(dirglob, sizeof(dirglob), "%s%c*", path,
                 PATH_SEP, group->group_id, PATH_SEP);
        if ((ffhandle = _findfirsti64(dirglob, &finfo)) == -1) {
            gsyserror(group, "Failed to open directory %s", path);
            return;
        }
        do {
            len = snprintf(filename, sizeof(filename), "%s%c%s", path,
                           PATH_SEP, finfo.name);
            if ((len >= sizeof(filename)) || (len == -1)) {
                glog0(group, "Max pathname length exceeded: %s%c%s",
                             filename, PATH_SEP, finfo.name);
                continue;
            }
            if (strcmp(finfo.name, ".") && strcmp(finfo.name, "..")) {
                clear_path(filename, group);
            }
        } while (_findnexti64(ffhandle, &finfo) == 0);
        _findclose(ffhandle);
#else
        DIR *dir;
        struct dirent *de;

        if ((dir = opendir(path)) == NULL) {
            gsyserror(group, "Failed to open directory %s", path);
            return;
        }
        // errno needs to be set to 0 before calling readdir, otherwise
        // we'll report a false error when we exhaust the directory
        while ((errno = 0, de = readdir(dir)) != NULL) {
            len = snprintf(filename, sizeof(filename), "%s%c%s", path, PATH_SEP,
                           de->d_name);
            if ((len >= sizeof(filename)) || (len == -1)) {
                glog0(group, "Max pathname length exceeded: %s%c%s",
                             path, PATH_SEP, de->d_name);
                continue;
            }
            if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
                clear_path(filename, group);
            }
        }
        if (errno && (errno != ENOENT)) {
            gsyserror(group, "Failed to read directory %s", path);
        }
        closedir(dir);
#endif
        if (rmdir(path) == -1) {
            gsyserror(group, "Failed remove directory %s", path);
        }
    }
}

/**
 * For the current file in a group, move the existing file to
 * the appropriate backup directory, if it exists.
 * In the event of a failure, delete the original file
 */
void move_to_backup(struct group_list_t *group)
{
    stat_struct statbuf;
    char backup_file[MAXBACKUPPATHNAME], *trim_name;
    int len;

    if (lstat_func(group->fileinfo.filepath, &statbuf) == -1) {
        return;
    }

    if (backupcnt == 0) {
        clear_path(group->fileinfo.filepath, group);
        return;
    }

#ifdef WINDOWS
    if ((group->fileinfo.filepath[1] == ':') &&
            (group->fileinfo.filepath[2] == '\\')) {
        trim_name = &group->fileinfo.filepath[3];
    } else {
        trim_name = group->fileinfo.filepath;
    }
#else
    trim_name = group->fileinfo.filepath;
#endif
    len = snprintf(backup_file, sizeof(backup_file), "%s%c%s%c%s%c%s",
                   backupdir[group->fileinfo.destdiridx], PATH_SEP,
                   group->start_date, PATH_SEP,
                   group->start_time, PATH_SEP, trim_name);
    if (len >= sizeof(backup_file)) {
        glog0(group, "Max pathname length exceeded for backup file, deleting",
                     group->fileinfo.filepath);
        clear_path(group->fileinfo.filepath, group);
        return;
    }
    clear_path(backup_file, group);
    if (!create_path_to_file(group, backup_file)) {
        glog0(group, "Error creating path to backup file");
        clear_path(group->fileinfo.filepath, group);
    }
#ifdef WINDOWS
    if (!MoveFile(group->fileinfo.filepath, backup_file)) {
        char errbuf[300];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
                GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
        glog0(group, "Couldn't rename from %s to %s, deleting: (%d): %s",
                group->fileinfo.filepath, backup_file, GetLastError(), errbuf);
        clear_path(group->fileinfo.filepath, group);
    } else {
        glog2(group, "Backed up existing file to %s", backup_file);
    }
#else
    if (rename(group->fileinfo.filepath, backup_file) == -1) {
        gsyserror(group, "Couldn't rename from %s to %s, deleting",
                         group->fileinfo.filepath, backup_file);
        clear_path(group->fileinfo.filepath, group);
    } else {
        glog2(group, "Backed up existing file to %s", backup_file);
    }
#endif
}

/**
 * Creates all directories in the given file's path, removing existing files.
 * Returns 1 on success, 0 on failure
 */
int create_path_to_file(struct group_list_t *group, const char *filename)
{
    char *dir, *base;
    stat_struct statbuf;
    int rval;

    split_path(filename, &dir, &base);
    if (!dir) {
        glog1(group, "Invalid path element %s", filename);
        rval = 0;
        goto end;
    }
#ifdef WINDOWS
    if ((base == NULL) || ((strlen(dir) == 2) && (dir[1] == ':'))) {
#else
    if ((!strcmp(dir, ".")) || (!strcmp(dir, "/"))) {
#endif
        // At top level directory, so stop recursion
        rval = 1;
        goto end;
    }

    if (lstat_func(dir, &statbuf) != -1) {
        if (!S_ISDIR(statbuf.st_mode)) {
            if (unlink(dir) == -1) {
                gsyserror(group, "Failed to delete path element %s", dir);
                rval = 0;
                goto end;
            }
            if (mkdir(dir, 0755) == -1) {
                gsyserror(group, "Failed to create path element %s", dir);
                rval = 0;
                goto end;
            }
        }
    } else {
        // If the file's directory does not exist, recurse first to make sure
        // all parent directories exist
        if (!create_path_to_file(group, dir)) {
            rval = 0;
            goto end;
        }
        if (mkdir(dir, 0755) == -1) {
            gsyserror(group, "Failed to create path element %s", dir);
            rval = 0;
            goto end;
        }
    }

    rval = 1;

end:
    free(dir);
    free(base);
    return rval;
}

void new_loss_event(struct group_list_t *group, uint16_t txseq)
{
    uint32_t seq_long;
    uint16_t count;
    int bytes, avgbytes, rate, grtt_usec;

    glog4(group, "Seq %d starts new loss event", txseq);
    // Found a new loss event
    if (txseq < group->max_txseq - MAXMISORDER) {
        glog5(group, "wrap check, i=%u, maxseq=%u", txseq, group->max_txseq);
        seq_long = ((group->seq_wrap - 1) << 16) | txseq;
    } else {
        seq_long = (group->seq_wrap << 16) | txseq;
    }
    if (group->slowstart) {
        group->slowstart = 0;
        // Initialize loss history 
        count = group->max_txseq;
        bytes = 0;
        grtt_usec = (int)(group->grtt * 1000000);
        while ((count != group->start_txseq) &&
                (diff_usec(group->loss_history[txseq].t,
                   group->loss_history[count].t) < grtt_usec)) {
            bytes += group->loss_history[count--].size;
        }
        rate = (int)(bytes / group->grtt);
        glog4(group, "End slowstart, calculated rate = %d", rate);
        avgbytes= bytes / ((int16_t)(group->max_txseq - count));
        group->loss_events[0].len = (int)(0 + pow(
                (rate * ((group->rtt != 0) ? group->rtt : group->grtt)) / 
                (sqrt(1.5) * 8 * avgbytes), 2));
        glog4(group, "Calculated prior event len = %d (rtt=%f, avgbytes=%d)",
                     group->loss_events[0].len, group->rtt,avgbytes);
    } else {
        group->loss_events[0].len = seq_long - group->loss_events[0].start_seq;
        glog4(group, "Prior event length = %d (i=%u, start=%u)",
                     group->loss_events[0].len,
                     seq_long, group->loss_events[0].start_seq);
    }
    memmove(&group->loss_events[1], &group->loss_events[0],
            sizeof(struct loss_event_t) * 8);
    group->loss_events[0].start_seq = seq_long;
    group->loss_events[0].len = 0;
    group->loss_events[0].t = group->loss_history[txseq].t;
}

/**
 * Updates the group's loss history
 *
 * Packets older than MAXMISORDER sequence numbers don't change the loss
 * history, and packets aren't considered lost unless the sequence number is
 * more than MAXMISORDER sequence numbers old.  Works under the assumption
 * that no more than 32K packets in a row get lost.
 */
void update_loss_history(struct group_list_t *group, uint16_t txseq, int size,
                         int ecn)
{
    uint16_t i;
    int tdiff, grtt_usec;
    struct timeval tvdiff;

    group->loss_history[txseq].found = 1;
    gettimeofday(&group->loss_history[txseq].t, NULL);
    if (group->multi.ss.ss_family == AF_INET6) {
        group->loss_history[txseq].size = size + 8 + 40;
    } else {
        group->loss_history[txseq].size = size + 8 + 20;
    }
    
    if ((int16_t)(txseq - group->max_txseq) > 0) {
        glog4(group, "Got seq %d, max was %d", txseq, group->max_txseq);
        grtt_usec = (int)(group->grtt * 1000000);
        if (txseq < group->max_txseq) {
            glog5(group, "increasing seq_wrap, txseq=%u, maxseq=%u",
                         txseq, group->max_txseq);
            group->seq_wrap++;
        }
        // First set nominal arrival times of missed packets
        for (i = group->max_txseq + 1; i != txseq; i++) {
            tdiff = (int)diff_usec(group->loss_history[txseq].t,
                                   group->loss_history[group->max_txseq].t) *
                ((i - group->max_txseq) / (txseq - group->max_txseq));
            tvdiff.tv_sec = 0;
            tvdiff.tv_usec = tdiff;
            while (tvdiff.tv_usec >= 1000000) {
                tvdiff.tv_usec -= 1000000;
                tvdiff.tv_sec++;
            }
            group->loss_history[i].found = 0;
            group->loss_history[i].t =
                    add_timeval(group->loss_history[group->max_txseq].t,tvdiff);
        }
        // Then check for missed packets up to MAXMISORDER less than the current
        // Don't do this part unless we have at least MAXMISORDER packets
        // TODO: address issue of start_txseq being within MAXMISORDER sequence
        // numbers from the maximum
        if (group->seq_wrap ||((uint16_t)(group->max_txseq -
                                    group->start_txseq) >= MAXMISORDER)) {
            for (i = group->max_txseq - MAXMISORDER;
                    i != (uint16_t)(txseq - MAXMISORDER); i++) {
                if (!group->loss_history[i].found &&
                        ((diff_usec(group->loss_history[i].t,
                                    group->loss_events[0].t) > grtt_usec) ||
                            group->slowstart)) {
                    new_loss_event(group, i);
                }
            }
        }
        group->max_txseq = txseq;
        if (ecn) {
            glog4(group, "Seq %d marked by ECN", txseq);
            if ((diff_usec(group->loss_history[txseq].t,
                    group->loss_events[0].t) > grtt_usec) || group->slowstart) {
                new_loss_event(group, txseq);
            }
        }
    }
    group->loss_events[0].len = ((group->seq_wrap << 16) | group->max_txseq) -
                                group->loss_events[0].start_seq;
    glog5(group, "current cc len = %d", group->loss_events[0].len);
    glog5(group, "seq_wrap=%d, max_txseq=%u, start_seq=%u",
            group->seq_wrap, group->max_txseq, group->loss_events[0].start_seq);
}

/**
 * Calculates and returns the loss event rate
 * TODO: add history discounting
 */
double loss_event_rate(struct group_list_t *group)
{
    double weights[8] = { 1.0, 1.0, 1.0, 1.0, 0.8, 0.6, 0.4, 0.2 };
    double loss_sum_cur, loss_sum_no_cur, weight_sum;
    int i;

    if (group->slowstart) {
        return 0.0;
    }

    loss_sum_cur = 0;
    loss_sum_no_cur = 0;
    weight_sum = 0;
    for (i = 0; i < 8; i++) {
        glog5(group, "loss_events[%d].len=%d", i, group->loss_events[i].len);
        if (group->loss_events[i].len != 0) {
            loss_sum_cur += group->loss_events[i].len * weights[i];
            weight_sum += weights[i];
        }
    }
    for (i = 1; i < 9; i++) {
        if (group->loss_events[i].len == 0) break;
        loss_sum_no_cur += group->loss_events[i].len * weights[i - 1];
    }
    glog5(group, "cur_sum=%f, cur_no_sum=%f, weight_sum=%f",
                 loss_sum_cur, loss_sum_no_cur, weight_sum);
    // Return inverse of larger average
    if (loss_sum_no_cur > loss_sum_cur) {
        return weight_sum / loss_sum_no_cur;
    } else {
        return weight_sum / loss_sum_cur;
    }
}

/**
 * Returns the current congestion control rate in bytes / second.
 * As specified in RFC 4654
 */
unsigned current_cc_rate(struct group_list_t *group)
{
    double p, rtt;
    int i, bytes, thresh;

    if (group->rtt != 0.0) {
        rtt = group->rtt;
    } else {
        rtt = group->grtt;
    }
    p = loss_event_rate(group);

    if (p == 0.0) {
        thresh = (int)(group->grtt * 1000000 * 4);
        bytes = 0;
        i = group->max_txseq;
        while ((i != group->start_txseq) &&
                (diff_usec(group->loss_history[group->max_txseq].t,
                   group->loss_history[i].t) < thresh)) {
            bytes += group->loss_history[i--].size;
        }
        return (unsigned)(2.0 * bytes / (4.0 * group->grtt));
    } else {
        glog5(group, "getting cc rate, p=%f, rtt=%f", p, rtt);
        return (unsigned)(group->datapacketsize /
                (rtt * (sqrt(p * 2.0 / 3.0) +
                        (12 * sqrt(p * 3.0 / 8.0) * p * (1 + (32 * p * p))))));
    }
}

