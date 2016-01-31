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
#include <errno.h>
#include <math.h>

#ifdef WINDOWS

#include "win_func.h"

#else // WINDOWS

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_loop.h"
#include "proxy_upstream.h"
#include "proxy_downstream.h"
#include "heartbeat_send.h"

/**
 * Gets the current timeout value to use for the main loop
 *
 * First check to see if any active groups have an expired timeout, and
 * handle that timeout.  Once all expired timeouts have been handled, find
 * the active group with the earliest timeout and return the time until that
 * timeout.  If there are no active groups, return NULL.
 */
struct timeval *getrecenttimeout(void)
{
    static struct timeval tv = {0,0};
    struct timeval current_timestamp, min_timestamp;
    int i, j, found_timeout, recheck, pending;
    struct pr_group_list_t *group;
    int32_t usecs;

    gettimeofday(&current_timestamp, NULL);

    recheck = 1;
    while (recheck) {
        found_timeout = 0;
        recheck = 0;
        // First check group timeouts
        for (i = 0; i < MAXLIST; i++) {
            group = &group_list[i];
            if (group->group_id != 0) {
                if ((group->phase == PR_PHASE_REGISTERED) ||
                        (group->phase == PR_PHASE_READY)) {
                    if ((group->phase == PR_PHASE_READY) &&
                            (cmptimestamp(current_timestamp,
                                    group->phase_timeout_time) >= 0)) {
                        send_keyinfo(group, NULL, 0);
                        recheck = 1;
                    }
                    if (cmptimestamp(current_timestamp,
                            group->phase_expire_time) >= 0) {
                        group->phase = PR_PHASE_RECEIVING;
                        check_unfinished_clients(group, 1);
                    }
                }
                if (cmptimestamp(current_timestamp, group->timeout_time) >= 0) {
                    // If at least one message is pending, timeout_time is
                    // time to next send of the specified message.
                    // Otherwise it's the overall timeout.
                    glog5(group, "timeout, checking pending");
                    for (pending = 0, j = 0; (j < MAX_PEND) && !pending; j++) {
                        if (group->pending[j].msg != 0) {
                            glog5(group, "found pending %s",
                                         func_name(group->pending[j].msg));
                            pending = 1;
                        }
                    }
                    if (pending) {
                        send_all_pending(group);
                    } else {
                        glog1(group, "Group timed out");
                        group_cleanup(group);
                    }
                    recheck = 1;
                }
                if (!recheck && ((!found_timeout) ||
                                 (cmptimestamp(group->timeout_time,
                                               min_timestamp) < 0))) {
                    min_timestamp = group->timeout_time;
                    found_timeout = 1;
                }
            }
        }
        // Then check timeout for sending heartbeat
        if (hbhost_count) {
            if (cmptimestamp(current_timestamp, next_hb_time) >= 0) {
                send_hb_request(listener, hb_hosts, hbhost_count,
                                &next_hb_time, hb_interval, uid);
                recheck = 1;
            } else if ((!found_timeout) ||
                       (cmptimestamp(next_hb_time, min_timestamp) < 0)) {
                min_timestamp = next_hb_time;
                found_timeout = 1;
            }
        }
    }
    if (found_timeout) {
        usecs = (int32_t)diff_usec(min_timestamp, current_timestamp);
        tv.tv_sec = usecs / 1000000;
        tv.tv_usec = usecs % 1000000;
        return &tv;
    } else {
        return NULL;
    }
}

/**
 * This is the main message reading loop.  Messages are read, validated,
 * decrypted if necessary, then passed to the appropriate routine for handling.
 */
void mainloop(void)
{
    struct uftp_h *header;
    struct pr_group_list_t *group;
    unsigned char *buf, *decrypted, *message;
    char rxname[INET6_ADDRSTRLEN];
    int packetlen, rval, hostidx, i;
    unsigned int decryptlen, meslen;
    uint8_t *func, tos;
    union sockaddr_u src;
    struct timeval *tv;
    double new_grtt;

    log2(0, 0, 0, "%s", VERSIONSTR);
    for (i = 0; i < key_count; i++) {
        if (privkey_type[i] == KEYBLOB_RSA) {
            log2(0, 0, 0, "Loaded %d bit RSA key with fingerprint %s",
                  RSA_keylen(privkey[i].rsa) * 8,
                  print_key_fingerprint(privkey[i], KEYBLOB_RSA));
        } else {
            log2(0, 0, 0, "Loaded ECDSA key with curve %s and fingerprint %s",
                  curve_name(get_EC_curve(privkey[i].ec)),
                  print_key_fingerprint(privkey[i], KEYBLOB_EC));
        }
    }

    buf = safe_calloc(MAXMTU, 1);
    decrypted = safe_calloc(MAXMTU, 1);
    header = (struct uftp_h *)buf;

    while (1) {
        tv = getrecenttimeout();
        if (tv) {
            log5(0, 0, 0, "timeout: %d.%06d", tv->tv_sec, tv->tv_usec);
        }
        if (read_packet(listener, &src, buf, &packetlen,
                        MAXMTU, tv, &tos) <= 0) {
            continue;
        }

        if ((rval = getnameinfo((struct sockaddr *)&src, family_len(src),
                rxname, sizeof(rxname), NULL, 0, NI_NUMERICHOST)) != 0) {
            log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
        }

        if (header->version != UFTP_VER_NUM) {
            log4(0, 0, 0, "Invalid message from %s: not uftp packet "
                    "or invalid version", rxname);
            continue;
        }
        if (packetlen < sizeof(struct uftp_h) + 4) {
            log4(0, 0, 0, "Invalid packet size from %s: %d", rxname, packetlen);
            continue;
        }

        if (addr_equal(&src, &out_if.su)) {
            // Packet from self -- drop
            continue;
        }
        if (header->func == HB_REQ) {
            handle_hb_request(&src, buf, packetlen);
            continue;
        }
        if (header->func == HB_RESP) {
            handle_hb_response(listener, &src, buf + sizeof(struct uftp_h),
                               packetlen - sizeof(struct uftp_h), hb_hosts,
                               hbhost_count, privkey[0], privkey_type[0], uid);
            continue;
        }
        if (header->func == KEY_REQ) {
            handle_key_req(&src, buf, packetlen);
            continue;
        }
        if (header->func == PROXY_KEY) {
            // Only clients handle these, so drop
            continue;
        }
        if ((proxy_type == SERVER_PROXY) && (addr_blank(&down_addr))) {
            log1(0, 0, 0, "Rejecting message from %s: downstream address "
                          "not established", rxname);
            continue;
        }

        group = find_group(ntohl(header->group_id), header->group_inst);
        if (header->func == ANNOUNCE) {
            handle_announce(group, &src, buf, packetlen);
        } else {
            if (group == NULL) {
                continue;
            }
            if (group->version != header->version) {
                glog1(group, "Version mismatch");
                continue;
            }
            if (proxy_type == SERVER_PROXY) {
                // Server proxies don't do anything outside of an ANNOUNCE.
                // Just send it on through.
                if (!memcmp(&src, &group->up_addr, sizeof(src))) {
                    new_grtt = unquantize_grtt(header->grtt);
                    if (fabs(new_grtt - group->grtt) > 0.001) {
                        group->grtt = new_grtt;
                        set_timeout(group, 0, 1);
                    }
                    group->gsize = unquantize_gsize(header->gsize);
                    glog4(group, "grtt: %.3f", group->grtt);
                }
                forward_message(group, &src, buf, packetlen);
                continue;
            }
            if (!memcmp(&src, &group->up_addr, sizeof(src))) {
                // Downstream message
                if (group->src_id != header->src_id) {
                    glog1(group, "Source ID mismatch");
                    continue;
                }
                new_grtt = unquantize_grtt(header->grtt);
                if (fabs(new_grtt - group->grtt) > 0.001) {
                    group->grtt = new_grtt;
                    set_timeout(group, 0, 1);
                }
                group->gsize = unquantize_gsize(header->gsize);
                glog4(group, "grtt: %.3f", group->grtt);
                message = buf + sizeof(struct uftp_h);
                meslen = packetlen - sizeof(struct uftp_h);
                if (header->func == ABORT) {
                    handle_abort(group, &src, message, meslen, header->src_id);
                } else if (header->func == KEYINFO) {
                    handle_keyinfo(group, message, meslen, header->src_id);
                } else if ((header->func == REG_CONF) &&
                           (group->keytype != KEY_NONE)) {
                    handle_regconf(group, message, meslen);
                } else {
                    // If we don't need to process the message, don't bother
                    // decrypting anything.  Just forward it on.
                    forward_message(group, &src, buf, packetlen);
                }
            } else {
                // Upstream message
                // Decrypt first if necessary
                hostidx = find_client(group, header->src_id);
                if ((hostidx == -1) && (header->func != REGISTER) &&
                        (header->func != CLIENT_KEY)) {
                    glog1(group, "Host %08X not in host list",
                                 ntohl(header->src_id));
                    continue;
                }
                if ((hostidx != -1) && (header->func == ENCRYPTED) &&
                        (group->keytype != KEY_NONE)) {
                    if (!validate_and_decrypt(buf, packetlen, &decrypted,
                            &decryptlen, group->keytype, group->groupkey,
                            group->groupsalt, group->ivlen, group->hashtype,
                            group->grouphmackey, group->hmaclen, group->sigtype,
                            group->keyextype, group->destinfo[hostidx].pubkey,
                            group->destinfo[hostidx].pubkeylen)) {
                        glog1(group, "Rejecting message from %s: "
                                     "decrypt/validate failed", rxname);
                        continue;
                    }
                    func = (uint8_t *)decrypted;
                    message = decrypted;
                    meslen = decryptlen;
                } else {
                    if ((hostidx != -1) &&
                            (group->keytype != KEY_NONE) &&
                            ((header->func == KEYINFO_ACK) ||
                             (header->func == FILEINFO_ACK) ||
                             (header->func == STATUS) ||
                             (header->func == COMPLETE))) {
                        glog1(group, "Rejecting %s message from %s: "
                                "not encrypted",func_name(header->func),rxname);
                        continue;
                    }
                    func = (uint8_t *)&header->func;
                    message = buf + sizeof(struct uftp_h);
                    meslen = packetlen - sizeof(struct uftp_h);
                }

                switch (*func) {
                case REGISTER:
                    handle_register(group, hostidx, message, meslen,
                                    header->src_id);
                    break;
                case CLIENT_KEY:
                    handle_clientkey(group, hostidx, message, meslen,
                                     header->src_id);
                    break;
                case KEYINFO_ACK:
                    handle_keyinfo_ack(group, hostidx, message, meslen);
                    break;
                case FILEINFO_ACK:
                    handle_fileinfo_ack(group, hostidx, message, meslen);
                    break;
                case STATUS:
                    handle_status(group, hostidx, message, meslen);
                    break;
                case COMPLETE:
                    handle_complete(group, hostidx, message, meslen);
                    break;
                case ABORT:
                    handle_abort(group, &src, message, meslen, header->src_id);
                    break;
                default:
                    forward_message(group, &src, buf, packetlen);
                    break;
                }
            }
        }
    }
}

