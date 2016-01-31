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

#include "client.h"
#include "client_common.h"
#include "client_loop.h"
#include "client_announce.h"
#include "client_fileinfo.h"
#include "client_transfer.h"
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
    int i, found_timeout, done, sent_naks;
    struct group_list_t *group;
    unsigned int section, nak_count;
    unsigned char *naks;

    gettimeofday(&current_timestamp, NULL);
    done = 0;
    while (!done) {
        found_timeout = 0;
        done = 1;
        for (i = 0; i < MAXLIST; i++) {
            group = &group_list[i];
            if (group->group_id != 0) {
                if (cmptimestamp(current_timestamp, group->timeout_time) >= 0) {
                    switch (group->phase) {
                    case PHASE_REGISTERED:
                        send_register(group);
                        break;
                    case PHASE_RECEIVING:
                    case PHASE_MIDGROUP:
                        glog1(group, "Transfer timed out");
                        send_abort(group, "Transfer timed out");
                        break;
                    case PHASE_COMPLETE:
                        send_complete(group, 0);
                        break;
                    }
                    done = 0;
                } else if ((!found_timeout) ||
                           (cmptimestamp(group->timeout_time,
                                         min_timestamp) < 0)) {
                    glog5(group, "found min timeout time: %d:%06d",
                                 group->timeout_time.tv_sec,
                                 group->timeout_time.tv_usec);
                    min_timestamp = group->timeout_time;
                    found_timeout = 1;
                }
                // Check for a NAK timeout for sending a STATUS or COMPLETE
                if ((group->fileinfo.nak_time.tv_sec != 0) &&
                        cmptimestamp(current_timestamp,
                                     group->fileinfo.nak_time) >= 0) {
                    group->fileinfo.nak_time.tv_sec = 0;
                    group->fileinfo.nak_time.tv_usec = 0;
                    // Send NAKs
                    sent_naks = 0;
                retry_naks:
                    for (section = group->fileinfo.nak_section_first;
                            section < group->fileinfo.nak_section_last;
                            section++) {
                        naks = NULL;
                        nak_count = get_naks(group, section, &naks);
                        glog3(group, "read %d NAKs for section %d",
                                     nak_count, section);
                        if (nak_count > 0) {
                            send_status(group, section, naks, nak_count);
                            sent_naks = 1;
                        }
                        free(naks);
                        naks = NULL;
                    }
                    if (file_done(group, 1)) {
                        glog2(group, "File transfer complete");
                        send_complete(group, 0);
                        file_cleanup(group, 0);
                    } else if (group->fileinfo.got_done && !sent_naks) {
                        // We didn't send any NAKs since the last time
                        // but the server is asking for some,
                        // so check all prior sections
                        group->fileinfo.nak_section_last = 
                                group->fileinfo.nak_section_first;
                        group->fileinfo.nak_section_first = 0;
                        group->fileinfo.got_done = 0;
                        goto retry_naks;
                    }
                } else if ((group->fileinfo.nak_time.tv_sec != 0) &&
                           ((!found_timeout) ||
                            (cmptimestamp(group->fileinfo.nak_time,
                                          min_timestamp) < 0))) {
                    glog5(group, "found min nak time: %d:%06d",
                         group->fileinfo.nak_time.tv_sec,
                         group->fileinfo.nak_time.tv_usec);
                    min_timestamp = group->fileinfo.nak_time;
                    found_timeout = 1;
                }
                // Check congestion control feedback timer
                if (!group->isclr) {
                    if ((group->cc_time.tv_sec != 0) &&
                            (cmptimestamp(current_timestamp,
                                          group->cc_time) >= 0)) {
                        send_cc_ack(group);
                    } else if ((group->cc_time.tv_sec != 0) &&
                               ((!found_timeout) ||
                                (cmptimestamp(group->cc_time,
                                              min_timestamp) < 0))) {
                        glog5(group, "found min CC time: %d:%06d",
                             group->cc_time.tv_sec, group->cc_time.tv_usec);
                        min_timestamp = group->cc_time;
                        found_timeout = 1;
                    }
                }
            }
        }
        // Check timeout for proxy key request
        if (has_proxy && (proxy_pubkey.key == 0)) {
            if (cmptimestamp(current_timestamp, next_keyreq_time) >= 0) {
                send_key_req();
                done = 0;
            } else if ((!found_timeout) ||
                       (cmptimestamp(next_keyreq_time, min_timestamp) < 0)) {
                min_timestamp = next_keyreq_time;
                found_timeout = 1;
            }
        }
        // Check timeout for sending heartbeat
        if (hbhost_count) {
            if (cmptimestamp(current_timestamp, next_hb_time) >= 0) {
                send_hb_request(listener, hb_hosts, hbhost_count,
                                &next_hb_time, hb_interval, uid);
                done = 0;
            } else if ((!found_timeout) ||
                       (cmptimestamp(next_hb_time, min_timestamp) < 0)) {
                min_timestamp = next_hb_time;
                found_timeout = 1;
            }
        }

    }
    if (found_timeout) {
        tv = diff_timeval(min_timestamp, current_timestamp);
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
    struct group_list_t *group;
    unsigned char *buf, *decrypted, *message;
    char rxname[INET6_ADDRSTRLEN];
    unsigned int decryptlen, meslen;
    int packetlen, rval, i, ecn;
    uint8_t version, *func, tos;
    uint16_t txseq;
    union sockaddr_u src;
    struct timeval *tv, rxtime;
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
            log5(0, 0, 0, "read timeout: %d.%06d", tv->tv_sec, tv->tv_usec);
        }
        if (read_packet(listener, &src, buf, &packetlen,
                        MAXMTU, tv, &tos) <= 0) {
            continue;
        }
        gettimeofday(&rxtime, NULL);

        if ((rval = getnameinfo((struct sockaddr *)&src, family_len(src),
                rxname, sizeof(rxname), NULL, 0, NI_NUMERICHOST)) != 0) {
            log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
        }

        if (header->version == UFTP_VER_NUM) {
            version = header->version;
            group = find_group(ntohl(header->group_id), header->group_inst);
        } else {
            log4(0, 0, 0, "Invalid message from %s: not uftp packet "
                          "or invalid version", rxname);
            continue;
        }
        if (packetlen < sizeof(struct uftp_h) + 4) {
            log4(0, 0, 0, "Invalid packet size from %s: %d", rxname, packetlen);
            continue;
        }

        txseq = htons(header->seq);
        // A KEY_INFO or ABORT could come from a proxy, so don't check the seq
        // TODO: need to account for these in the loss history
        if ((group != NULL) && (header->func != KEYINFO) &&
                (header->func != ABORT)) {
            if ((int16_t)(group->max_txseq - txseq) > MAXMISORDER) {
                glog3(group, "seq out of range, dropping");
                continue;
            }
            if (group->cc_type != CC_NONE) {
                ecn = ((tos & 0x3) == 3);
                update_loss_history(group, txseq, packetlen, ecn);
            } else if ((int16_t)(txseq - group->max_txseq) > 0) {
                group->max_txseq = txseq;
            }
        }

        if ((header->func == ENCRYPTED) && (group != NULL) &&
                (group->keytype != KEY_NONE)) {
            if (group->phase == PHASE_REGISTERED) {
                glog1(group, "Got encrypted packet from %s "
                             "but keys not established", rxname);
            }

            if (!validate_and_decrypt(buf, packetlen, &decrypted, &decryptlen,
                    group->keytype, group->groupkey, group->groupsalt,
                    group->ivlen, group->hashtype, group->grouphmackey,
                    group->hmaclen, group->sigtype, group->keyextype,
                    group->server_pubkey, group->server_pubkeylen)) {
                glog1(group, "Rejecting message from %s: "
                             "decrypt/validate failed", rxname);
                continue;
            }
            func = (uint8_t *)decrypted;
            message = decrypted;
            meslen = decryptlen;
        } else {
            if ((group != NULL) && (group->keytype != KEY_NONE) &&
                    ((header->func == FILEINFO) || (header->func == FILESEG) ||
                     (header->func == DONE) || (header->func == DONE_CONF) ||
                     ((header->func == ABORT) &&
                         (group->phase != PHASE_REGISTERED)))) {
                glog1(group, "Rejecting %s message from %s: not encrypted",
                             func_name(header->func), rxname);
                continue;
            }
            func = (uint8_t *)&header->func;
            message = buf + sizeof(struct uftp_h);
            meslen = packetlen - sizeof(struct uftp_h);
        }

        if (group != NULL) {
            new_grtt = unquantize_grtt(header->grtt);
            if (fabs(new_grtt - group->grtt) > 0.001) {
                group->grtt = new_grtt;
                set_timeout(group, 1);
            }
            group->gsize = unquantize_gsize(header->gsize);
            glog5(group, "grtt: %.3f", group->grtt);
        }

        if (header->func == PROXY_KEY) {
            handle_proxy_key(&src, message, meslen);
            continue;
        }
        if (header->func == HB_RESP) {
            handle_hb_response(listener, &src, message, meslen, hb_hosts,
                               hbhost_count, privkey[0], privkey_type[0], uid);
            continue;
        }
        if (header->func == ANNOUNCE) {
            // Ignore any ANNOUNCE for a group we're already handling
            if (group == NULL) {
                handle_announce(&src, buf, packetlen, rxtime);
            } else if (group->phase == PHASE_MIDGROUP) {
                // Make sure we don't time out while waiting for other
                // clients to register with the server.
                set_timeout(group, 0);
            }
        } else {
            if (group == NULL) {
                // group / file ID not in list
                continue;
            }
            if (group->version != version) {
                glog1(group, "Version mismatch");
                continue;
            }
            if (group->src_id != header->src_id) {
                glog1(group, "Source ID mismatch");
                continue;
            }
            if (*func == ABORT) {
                handle_abort(group, message, meslen);
                continue;
            }
            switch (group->phase) {
            case PHASE_REGISTERED:
                if (group->keytype != KEY_NONE) {
                    if (*func == KEYINFO) {
                        handle_keyinfo(group, message, meslen, header->src_id);
                    } else {
                        glog1(group, "Expected KEYINFO, got %s",
                                     func_name(*func));
                    }
                } else if (group->keytype == KEY_NONE) {
                    if (*func == REG_CONF) {
                        handle_regconf(group, message, meslen);
                    } else if (*func == FILEINFO) {
                        handle_fileinfo(group, message, meslen, rxtime);
                    } else {
                        glog1(group, "Expected REG_CONF, got %s",
                                     func_name(*func));
                    }
                }
                break;
            case PHASE_MIDGROUP:
                if (*func == FILEINFO) {
                    handle_fileinfo(group, message, meslen, rxtime);
                } else if (*func == KEYINFO) {
                    handle_keyinfo(group, message, meslen, header->src_id);
                } else if (*func == DONE) {
                    handle_done(group, message, meslen);
                } else {
                    // Other clients may be still getting earlier files or
                    // setting up, so silently ignore anything unexpected
                    // and reset the timeout.
                    set_timeout(group, 0);
                }
                break;
            case PHASE_RECEIVING:
                if (*func == FILEINFO) {
                    handle_fileinfo(group, message, meslen, rxtime);
                } else if (*func == FILESEG) {
                    handle_fileseg(group, message, meslen, txseq);
                } else if (*func == DONE) {
                    handle_done(group, message, meslen);
                } else if (*func == CONG_CTRL) {
                    handle_cong_ctrl(group, message, meslen, rxtime);
                }
                break;
            case PHASE_COMPLETE:
                if (*func == DONE_CONF) {
                    handle_done_conf(group, message, meslen);
                }
                break;
            }
        }
    }
}

