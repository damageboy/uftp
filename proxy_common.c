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

#ifdef WINDOWS

#include <ws2tcpip.h>
#include <io.h>

#include "win_func.h"

#else  // if WINDOWS

#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_upstream.h"

/**                    
 * Look for a given group in the global group list
 * Returns a pointer to the group in the list, or NULL if not found
 */
struct pr_group_list_t *find_group(uint32_t group_id, uint8_t group_inst)
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
 * Look for a given client in the group's client list
 * Returns the client's index in the list, or -1 if not found
 */
int find_client(struct pr_group_list_t *group, uint32_t id)
{
    int i;

    for (i = 0; i < group->destcount; i++) {
        if (group->destinfo[i].id == id) {
            return i;
        }
    }
    return -1;
}

/**
 * Checks to see if the multicast address used for the given group list member
 * is also being used by either another member or the public address list
 */
int other_mcast_users(struct pr_group_list_t *group)
{
    int i;

    for (i = 0; i < pub_multi_count; i++) {
        if (addr_equal(&group->privatemcast, &pub_multi[i])) {
            return 1;
        }
    }
    for (i = 0; i < MAXLIST; i++) {
        if ((&group_list[i] != group) && (group_list[i].group_id != 0) &&
                (addr_equal(&group->privatemcast,
                            &group_list[i].privatemcast))) {
            return 1;
        }
    }
    return 0;
}

/**
 * Clean up a group list entry.  Free malloc'ed structures, drop the
 * multicast group (if no one else is using it) and free the slot.
 */
void group_cleanup(struct pr_group_list_t *group)
{
    int i;

    for (i = 0; i < MAX_PEND; i++) {
        free(group->pending[i].naklist);
    }

    if (!addr_blank(&group->privatemcast) && (proxy_type != CLIENT_PROXY) &&
            !other_mcast_users(group) && group->multi_join) {
        multicast_leave(listener, group->group_id, &group->privatemcast,
                m_interface, interface_count, server_fp, server_fp_count);
    }
    if (group->server_pubkey.key) {
        if ((group->keyextype == KEYEX_RSA) ||
                (group->keyextype == KEYEX_ECDH_RSA)) {
            free_RSA_key(group->server_pubkey.rsa);
        } else {
            free_EC_key(group->server_pubkey.ec);
        }
        if ((group->keyextype == KEYEX_ECDH_RSA) ||
                (group->keyextype == KEYEX_ECDH_ECDSA)) {
            free_EC_key(group->server_dhkey.ec);
            free_EC_key(group->proxy_dhkey.ec);
        }
    }
    for (i = 0; i < group->destcount; i++) {
        if (group->destinfo[i].pubkey.key) {
            if ((group->keyextype == KEYEX_RSA) ||
                    (group->keyextype == KEYEX_ECDH_RSA)) {
                free_RSA_key(group->destinfo[i].pubkey.rsa);
            } else {
                free_EC_key(group->destinfo[i].pubkey.ec);
            }
            if ((group->keyextype == KEYEX_ECDH_RSA) ||
                    (group->keyextype == KEYEX_ECDH_ECDSA)) {
                free_EC_key(group->destinfo[i].dhkey.ec);
            }
        }
    }
    memset(group, 0, sizeof(struct pr_group_list_t));
}

/**
 * Initializes the uftp header of an outgoing packet
 */
void set_uftp_header(struct uftp_h *header, int func,
                     struct pr_group_list_t *group)
{
    header->version = group->version;
    header->func = func;
    header->group_id = htonl(group->group_id);
    header->group_inst = group->group_inst;
    header->src_id = uid;
    switch (func) {
    case REGISTER:
    case KEYINFO_ACK:
    case FILEINFO_ACK:
    case STATUS:
    case COMPLETE:
        header->seq = htons(group->send_seq_up++);
        break;
    case KEYINFO:
        header->seq = 0;
        header->src_id = group->src_id;
        header->grtt = quantize_grtt(group->grtt);
        header->gsize = quantize_gsize(group->gsize);
        break;
    }
    // ABORTs will set seq and src_id themselves depending on the direction
}

/**
 * Sets the timeout time for a given group list member
 */
void set_timeout(struct pr_group_list_t *group, int pending_reset, int rescale)
{
    int pending, i;

    if (group->phase == PR_PHASE_READY) {
        if (!rescale) {
            gettimeofday(&group->start_phase_timeout_time, NULL);
        }
        group->phase_timeout_time = group->start_phase_timeout_time;
        add_timeval_d(&group->phase_timeout_time, 2 * group->grtt);
    }

    glog5(group, "set timeout: pending_reset=%d", pending_reset);
    for (pending = 0, i = 0; (i < MAX_PEND) && !pending; i++) {
        if (group->pending[i].msg != 0) {
            glog5(group, "set timeout: found pending %s",
                         func_name(group->pending[i].msg));
            pending = group->pending[i].msg;
        }
    }
    if (pending) {
        if (pending_reset) {
            if (!rescale) {
                gettimeofday(&group->start_timeout_time, NULL);
            }
            group->timeout_time = group->start_timeout_time;
            add_timeval_d(&group->timeout_time, 1 * group->grtt);
        }
    } else {
        if (!rescale) {
            gettimeofday(&group->start_timeout_time, NULL);
        }
        group->timeout_time = group->start_timeout_time;
        if (group->robust * group->grtt < 1.0) {
            add_timeval_d(&group->timeout_time, 1.0);
        } else {
            add_timeval_d(&group->timeout_time, group->robust * group->grtt);
        }
    }
}

/**
 * Returns the maximum number of clients that can be listed in a given message
 */
int max_msg_dest(struct pr_group_list_t *group, int func, int hlen)
{
    switch (func) {
    case REGISTER:
        return (group->blocksize / sizeof(uint32_t));
    case KEYINFO:
        return (group->blocksize / sizeof(struct destkey));
    case FILEINFO_ACK:
        return (group->blocksize / sizeof(uint32_t));
    case COMPLETE:
        return (group->blocksize / sizeof(uint32_t));
    default:
        return 0;
    }
}

/**
 * Sends a pending aggregate message for a given group and message
 */
void send_pending(struct pr_group_list_t *group, int pendidx)
{
    switch (group->pending[pendidx].msg) {
    case REGISTER:
        send_register(group, pendidx);
        break;
    case FILEINFO_ACK:
        send_fileinfo_ack(group, pendidx);
        break;
    case STATUS:
        send_status(group, pendidx);
        break;
    case COMPLETE:
        send_complete(group, pendidx);
        break;
    default:
        glog1(group, "Tried to send pending on invalid type %s",
                     func_name(group->pending[pendidx].msg));
        return;
    }
    if ((group->pending[pendidx].count <= 0) ||
            (group->pending[pendidx].msg == STATUS)) {
        // Finish the cleanup we started in load_pending
        // Always do this for a STATUS, since we don't have a pending list
        free(group->pending[pendidx].naklist);
        memset(&group->pending[pendidx], 0, sizeof(struct pr_pending_info_t));
    }
}

/**
 * Sends all pending aggregate message for a given group
 */
void send_all_pending(struct pr_group_list_t *group)
{
    int i;

    for (i = 0; i < MAX_PEND; i++) {
        if (group->pending[i].msg != 0) {
            send_pending(group, i);
        }
    }
}

/**
 * Add the NAKs in the given STATUS message to the list of pending NAKs
 */
void add_naks_to_pending(struct pr_group_list_t *group, int pendidx,
                         const unsigned char *message)
{
    const unsigned char *naks;
    unsigned i;

    naks = message + sizeof(struct status_h);
    for (i = 0; i < group->blocksize; i++) {
        group->pending[pendidx].naklist[i] |= naks[i];
    }
}

/**
 * Puts the given message on the pending message list.  If it doesn't match
 * any pending message and there are no open slots, first send what's pending.
 * If the pending list is full after adding the given message, then send.
 */
void check_pending(struct pr_group_list_t *group, int hostidx,
                   const unsigned char *message)
{
    const struct fileinfoack_h *fileinfoack;
    const struct status_h *status;
    const struct complete_h *complete;
    const uint8_t *func;
    struct pr_pending_info_t *pending;
    int match, pendidx, hlen;

    func = message;
    fileinfoack = (const struct fileinfoack_h *)message;
    status = (const struct status_h *)message;
    complete = (const struct complete_h *)message;

    glog3(group, "check_timeout: looking for pending %s", func_name(*func));
    for (pendidx = 0; pendidx < MAX_PEND; pendidx++) {
        pending = &group->pending[pendidx];
        if (group->pending[pendidx].msg == 0) {
            glog3(group, "check_timeout: found empty slot %d", pendidx);
            match = 1;
            break;
        }

        match = (*func == pending->msg);
        switch (*func) {
        case REGISTER:
            // REGISTER always matches itself
            break;
        case FILEINFO_ACK:
            match = match && (ntohs(fileinfoack->file_id) == pending->file_id);
            break;
        case STATUS:
            match = match && ((ntohs(status->file_id) == pending->file_id) &&
                              (ntohs(status->section) == pending->section));
            break;
        case COMPLETE:
            match = match && ((ntohs(complete->file_id) == pending->file_id) &&
                              (complete->status == pending->comp_status));
            break;
        default:
            glog1(group, "Tried to check pending on invalid type %s",
                         func_name(*func));
            return;
        }
        if (match) {
            break;
        }
    }

    if (!match) {
        send_all_pending(group);
        pendidx = 0;
        pending = &group->pending[pendidx];
    }

    glog3(group, "check_timeout: found match at slot %d", pendidx);
    pending->msg = *func;
    if (group->destinfo[hostidx].pending != pendidx) {
        group->destinfo[hostidx].pending = pendidx;
        pending->count++;
    }

    switch (*func) {
    case REGISTER:
        hlen = sizeof(struct register_h);
        if (pending->count == 1) {
            gettimeofday(&pending->rx_tstamp, NULL);
            pending->tstamp = group->destinfo[hostidx].regtime;
            glog3(group, "send time = %d.%06d",
                         pending->tstamp.tv_sec, pending->tstamp.tv_usec);
            glog3(group, "rx time = %d.%06d",
                         pending->rx_tstamp.tv_sec, pending->rx_tstamp.tv_usec);
        }
        break;
    case FILEINFO_ACK:
        hlen = sizeof(struct fileinfoack_h);
        if (pending->count == 1) {
            pending->partial = 1;
            gettimeofday(&pending->rx_tstamp, NULL);
            pending->tstamp.tv_sec = ntohl(fileinfoack->tstamp_sec);
            pending->tstamp.tv_usec = ntohl(fileinfoack->tstamp_usec);
            glog3(group, "send time = %d.%06d",
                         pending->tstamp.tv_sec, pending->tstamp.tv_usec);
            glog3(group, "rx time = %d.%06d",
                         pending->rx_tstamp.tv_sec, pending->rx_tstamp.tv_usec);
        }
        pending->file_id = ntohs(fileinfoack->file_id);
        pending->partial = pending->partial &&
                            ((fileinfoack->flags & FLAG_PARTIAL) != 0);
        break;
    case STATUS:
        hlen = sizeof(struct status_h);
        pending->file_id = ntohs(status->file_id);
        pending->section = ntohs(status->section);
        if (!pending->naklist) {
            pending->naklist = safe_calloc(group->blocksize, 1);
        }
        add_naks_to_pending(group, pendidx, message);
        break;
    case COMPLETE:
        hlen = sizeof(struct complete_h);
        pending->file_id = ntohs(complete->file_id);
        pending->comp_status = complete->status;
        break;
    }

    if ((*func != STATUS) &&
            (pending->count == max_msg_dest(group, *func, hlen))) {
        send_pending(group, pendidx);
    } else {
        int total_pending, i;

        glog3(group, "check_timeout: getting pending count for %s",
                     func_name(*func));
        for (total_pending = 0, i = 0; i < MAX_PEND; i++) {
            glog3(group, "check_timeout: adding %d pending for %d",
                         group->pending[i].count, i);
            total_pending += group->pending[i].count;
        }
        if (total_pending == 1) {
            set_timeout(group, 1, 0);
        }
    }
}

/**
 * Check for any client that hasn't fully registered.
 * If the abort parameter is set, send an ABORT to the server and client.
 * Returns 1 if any aren't fully registered, 0 if all are registered.
 */
int check_unfinished_clients(struct pr_group_list_t *group, int abort_session)
{
    int hostidx, found;
    struct pr_destinfo_t *dest;

    if (group->keytype == KEY_NONE) {
        return 0;
    }

    found = 0;
    for (hostidx = 0; hostidx < group->destcount; hostidx++) {
        dest = &group->destinfo[hostidx];
        if ((group->group_id != 0) &&
                (dest->state != PR_CLIENT_READY)) {
            if (abort_session) {
                send_downstream_abort(group, dest->id,
                        "Client not fully registered at proxy", 0);
                send_upstream_abort(group, dest->id,
                        "Client not fully registered at proxy");
            }
            found = 1;
        }
    }
    return found;
}

/**
 * Load a message body with the list of pending clients
 */
int load_pending(struct pr_group_list_t *group, int pendidx, int func,
                 uint32_t *addrlist, int listlen)
{
    int hostidx, cnt;
    struct pr_destinfo_t *dest;

    for (cnt = 0, hostidx = 0;
            (hostidx < group->destcount) && (cnt < listlen); hostidx++) {
        dest = &group->destinfo[hostidx];
        if (dest->pending == pendidx) {
            addrlist[cnt++] = dest->id;
            dest->pending = -1;
            group->pending[pendidx].count--;
        }
    }
    if (group->pending[pendidx].count <= 0) {
        // Don't zero out the whole pending struct.
        // We need to clear the message now to set timeouts properly but
        // we still use the other fields just before sending the message.
        // The full cleanup is done in send_pending
        group->pending[pendidx].count = 0;
        group->pending[pendidx].msg = 0;
    }

    return cnt;
}

/**
 * Forward a message unmodified to the next hop, resigning if necessary.
 */
void forward_message(struct pr_group_list_t *group,
                     const union sockaddr_u *src,
                     unsigned char *packet, int packetlen)
{
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    struct announce_h *announce;
    struct enc_info_he *encinfo;
    union sockaddr_u dest;
    unsigned int meslen, siglen;
    int hostidx, rval, iplen, resign;
    char destname[INET6_ADDRSTRLEN], destport[PORTNAME_LEN];
    uint8_t *sig, *sigcopy;
    union key_t key;

    header = (struct uftp_h *)packet;
    meslen = (unsigned int)packetlen;

    memset(&dest, 0, sizeof(dest));
    if (!memcmp(src, &group->up_addr, sizeof(*src))) {
        if (proxy_type == RESPONSE_PROXY) {
            // Response proxy, no downstream forwarding
            set_timeout(group, 0, 0);
            return;
        } else if (proxy_type == SERVER_PROXY) {
            dest = down_addr;
        } else {
            if (header->func == ANNOUNCE) {
                dest = group->publicmcast;
            } else {
                dest = group->privatemcast;
            }
            key = group->server_pubkey;
        }
    } else {
        dest = group->up_addr;
        if (proxy_type != SERVER_PROXY) {
            hostidx = find_client(group, header->src_id);
            if (hostidx == -1) {
                glog1(group, "Couldn't find receiver in list");
                return;
            }
            key = group->destinfo[hostidx].pubkey;
        }
    }

    // If we're using KEYEX signatures, or sending an ANNOUNCE with ECDH,
    // verify the signature and resign
    resign = 0;
    if ((proxy_type != SERVER_PROXY) && (header->func == ENCRYPTED) &&
            (group->sigtype == SIG_KEYEX)) {
        encrypted = (struct encrypted_h *)(packet + sizeof(struct uftp_h));
        sig = (uint8_t *)encrypted + sizeof(struct encrypted_h);
        siglen = ntohs(encrypted->sig_len);
        resign = 1;
    } else if ((proxy_type != SERVER_PROXY) && (header->func == ANNOUNCE) &&
            ((group->keyextype == KEYEX_ECDH_RSA) ||
             (group->keyextype == KEYEX_ECDH_ECDSA))) {
        announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
        iplen = ((announce->flags & FLAG_IPV6) != 0) ? 16 : 4;
        encinfo = (struct enc_info_he *) ((uint8_t *)announce +
                sizeof(struct announce_h) + iplen + iplen);
        sig = (uint8_t *)encinfo + sizeof(struct enc_info_he) +
                ntohs(encinfo->keylen) + ntohs(encinfo->dhlen);
        siglen = ntohs(encinfo->siglen);
        resign = 1;
    }
    if (resign) {
        sigcopy = safe_calloc(siglen, 1);
        memcpy(sigcopy, sig, siglen);
        memset(sig, 0, siglen);
        if ((group->keyextype == KEYEX_RSA) ||
                (group->keyextype == KEYEX_ECDH_RSA)) {
            if (header->func == ENCRYPTED) {
                if (!verify_RSA_sig(key.rsa, group->hashtype, packet,
                                    meslen, sigcopy, siglen)) {
                    glog1(group, "Signature verification failed");
                    free(sigcopy);
                    return;
                }
            }
            if (!create_RSA_sig(group->proxy_privkey.rsa, group->hashtype,
                                packet, meslen, sigcopy, &siglen)) {
                glog0(group, "Signature creation failed");
                free(sigcopy);
                return;
            }
        } else {
            if (header->func == ENCRYPTED) {
                if (!verify_ECDSA_sig(key.ec, group->hashtype, packet,
                                      meslen, sigcopy, siglen)) {
                    glog1(group, "Signature verification failed");
                    free(sigcopy);
                    return;
                }
            }
            if (!create_ECDSA_sig(group->proxy_privkey.ec, group->hashtype,
                                  packet, meslen, sigcopy, &siglen)) {
                glog0(group, "Signature creation failed");
                free(sigcopy);
                return;
            }
        }
        memcpy(sig, sigcopy, siglen);
        free(sigcopy);
    }

    if (nb_sendto(listener, packet, meslen, 0, (struct sockaddr *)&dest,
               family_len(dest)) == SOCKET_ERROR) {
        gsockerror(group, "Error forwarding message");
        if ((rval = getnameinfo((struct sockaddr *)&dest, family_len(dest),
                destname, sizeof(destname), destport, sizeof(destport),
                NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
            glog1(group, "getnameinfo failed: %s", gai_strerror(rval));
        }
        glog2(group, "Dest: %s:%s", destname, destport);
    }
    set_timeout(group, 0, 0);
}

/**
 * Process an HB_REQ message
 */
void handle_hb_request(const union sockaddr_u *src,
                       unsigned char *packet, unsigned packetlen)
{
    struct hb_req_h *hbreq;
    unsigned char *keyblob, *sig;
    union key_t key;
    unsigned char fingerprint[HMAC_LEN];
    unsigned int fplen, bloblen, siglen;
    char destname[INET6_ADDRSTRLEN], destport[PORTNAME_LEN];
    int resp, rval;

    hbreq = (struct hb_req_h *)(packet + sizeof(struct uftp_h));

    if ((rval = getnameinfo((const struct sockaddr *)src, family_len(*src),
            destname, sizeof(destname), destport, sizeof(destport),
            NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
    }
    if ((packetlen < sizeof(struct uftp_h) + (hbreq->hlen * 4)) ||
            ((hbreq->hlen * 4) < sizeof(struct hb_req_h))) {
        log1(0,0,0, "Rejecting HB_REQ from %s: invalid message size", destname);
        return;
    }
    log2(0, 0, 0, "Received HB_REQ from %s", destname);
    if ((proxy_type == SERVER_PROXY) && have_down_fingerprint) {
        if (addr_equal(&down_addr, src)) {
            resp = HB_AUTH_OK;
        } else if (down_nonce != ntohl(hbreq->nonce)) {
            resp = HB_AUTH_CHALLENGE;
        } else {
            keyblob = (unsigned char *)hbreq + sizeof(struct hb_req_h);
            bloblen = ntohs(hbreq->bloblen);
            sig = keyblob + bloblen;
            siglen = ntohs(hbreq->siglen);

            // First check key fingerprint, then check signature
            if (keyblob[0] == KEYBLOB_RSA) {
                if (!import_RSA_key(&key.rsa, keyblob, bloblen)) {
                    log1(0, 0, 0, "Failed to import public key from HB_REQ");
                    resp = HB_AUTH_FAILED;
                    goto end;
                } 

                hash(HASH_SHA1, keyblob, bloblen, fingerprint, &fplen);
                if (memcmp(down_fingerprint, fingerprint, fplen)) {
                    log1(0, 0, 0, "Failed to verify HB_REQ fingerprint");
                    resp = HB_AUTH_FAILED;
                    goto end;
                }

                if (!verify_RSA_sig(key.rsa, HASH_SHA1,
                        (unsigned char *)&hbreq->nonce,
                        sizeof(hbreq->nonce), sig, siglen)) {
                    log1(0, 0, 0, "Failed to verify HB_REQ signature");
                    resp = HB_AUTH_FAILED;
                    goto end;
                }
            } else {
                if (!import_EC_key(&key.ec, keyblob, bloblen, 0)) {
                    log1(0, 0, 0, "Failed to import public key from HB_REQ");
                    resp = HB_AUTH_FAILED;
                    goto end;
                } 

                hash(HASH_SHA1, keyblob, bloblen, fingerprint, &fplen);
                if (memcmp(down_fingerprint, fingerprint, fplen)) {
                    log1(0, 0, 0, "Failed to verify HB_REQ fingerprint");
                    resp = HB_AUTH_FAILED;
                    goto end;
                }

                if (!verify_ECDSA_sig(key.ec, HASH_SHA1,
                        (unsigned char *)&hbreq->nonce,
                        sizeof(hbreq->nonce), sig, siglen)) {
                    log1(0, 0, 0, "Failed to verify HB_REQ signature");
                    resp = HB_AUTH_FAILED;
                    goto end;
                }
            }

            down_addr = *src;
            log2(0, 0, 0, "Using %s:%s as downstream address:port",
                       destname, destport);
            down_nonce = rand32();
            resp = HB_AUTH_OK;
        }
    } else {
        resp = HB_AUTH_OK;
    }

end:
    send_hb_response(src, resp);
}

/**
 * Process an KEY_REQ message
 */
void handle_key_req(const union sockaddr_u *src,
                    const unsigned char *packet, unsigned packetlen)
{
    const struct key_req_h *keyreq;
    struct timeval current_timestamp;
    char destname[INET6_ADDRSTRLEN];
    int rval;

    keyreq = (const struct key_req_h *)(packet + sizeof(struct uftp_h));

    if ((rval = getnameinfo((const struct sockaddr *)src, family_len(*src),
            destname, sizeof(destname), NULL, 0, NI_NUMERICHOST)) != 0) {
        log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
    }
    if ((packetlen < sizeof(struct uftp_h) + (keyreq->hlen * 4U)) ||
            ((keyreq->hlen * 4U) < sizeof(struct key_req_h))) {
        log1(0,0,0,"Rejecting KEY_REQ from %s: invalid message size", destname);
        return;
    }
    log2(0, 0, 0, "Received KEY_REQ from %s", destname);

    gettimeofday(&current_timestamp, NULL);
    if (diff_sec(current_timestamp, last_key_req) > KEY_REQ_LIMIT) {
        send_proxy_key();
    }
}

/**
 * Sends an HB_RESP in response to an HB_REQ
 */
void send_hb_response(const union sockaddr_u *src, int response)
{
    unsigned char *packet;
    struct uftp_h *header;
    struct hb_resp_h *hbresp;
    char destname[INET6_ADDRSTRLEN], destport[PORTNAME_LEN];
    int meslen, rval;

    packet = safe_calloc(sizeof(struct uftp_h) + sizeof(struct hb_resp_h), 1);

    header = (struct uftp_h *)packet;
    hbresp = (struct hb_resp_h *)(packet + sizeof(struct uftp_h));
    header->version = UFTP_VER_NUM;
    header->func = HB_RESP;
    header->src_id = uid;
    hbresp->func = HB_RESP;
    hbresp->hlen = sizeof(struct hb_resp_h) / 4;
    hbresp->authenticated = response;
    if (response == HB_AUTH_CHALLENGE) {
        hbresp->nonce = htonl(down_nonce);
    }

    meslen = sizeof(struct uftp_h) + sizeof(struct hb_resp_h);
    if (nb_sendto(listener, packet, meslen, 0, (const struct sockaddr *)src,
                  family_len(*src)) == SOCKET_ERROR) {
        sockerror(0, 0, 0, "Error sending HB_RESP");
    } else {
        if ((rval = getnameinfo((const struct sockaddr *)src,
                family_len(*src), destname, sizeof(destname), destport,
                sizeof(destport), NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
            log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
        }
        log2(0, 0, 0, "Sent HB_RESP to %s:%s", destname, destport);
    }
    free(packet);
}

/**
 * Sends a PROXY_KEY message to the first listed public multicast address.
 */
void send_proxy_key()
{
    unsigned char *packet, *keyblob, *dhblob, *sig;
    struct uftp_h *header;
    struct proxy_key_h *proxykey;
    uint32_t nonce;
    unsigned int meslen, siglen;
    uint16_t bloblen, dhlen;
    char pubname[INET6_ADDRSTRLEN];
    int rval;

    packet = safe_calloc(sizeof(struct uftp_h) + sizeof(struct hb_req_h) +
                    (PUBKEY_LEN * 3) , 1);

    header = (struct uftp_h *)packet;
    proxykey = (struct proxy_key_h *)(packet + sizeof(struct uftp_h));
    keyblob = (unsigned char *)proxykey + sizeof(struct proxy_key_h);
    header->version = UFTP_VER_NUM;
    header->func = PROXY_KEY;
    header->src_id = uid;
    proxykey->func = PROXY_KEY;
    nonce = htonl(rand32());
    proxykey->nonce = nonce;

    if (privkey_type[0] == KEYBLOB_RSA) {
        if (!export_RSA_key(privkey[0].rsa, keyblob, &bloblen)) {
            log0(0, 0, 0, "Error exporting public key");
            free(packet);
            return;
        }
    } else {
        if (!export_EC_key(privkey[0].ec, keyblob, &bloblen)) {
            log0(0, 0, 0, "Error exporting public key");
            free(packet);
            return;
        }
    }
    dhblob = keyblob + bloblen;
    if (dhkey.key) {
        if (!export_EC_key(dhkey.ec, dhblob, &dhlen)) {
            log0(0, 0, 0, "Error exporting public key");
            free(packet);
            return;
        }
    } else {
        dhlen = 0;
    }
    sig = dhblob + dhlen;
    if (privkey_type[0] == KEYBLOB_RSA) {
        if (!create_RSA_sig(privkey[0].rsa, HASH_SHA1, (unsigned char *)&nonce,
                            sizeof(nonce), sig, &siglen)) {
            log0(0, 0, 0, "Error signing nonce");
            free(packet);
            return;
        }
    } else {
        if (!create_ECDSA_sig(privkey[0].ec, HASH_SHA1, (unsigned char *)&nonce,
                              sizeof(nonce), sig, &siglen)) {
            log0(0, 0, 0, "Error signing nonce");
            free(packet);
            return;
        }
    }
    proxykey->bloblen = htons(bloblen);
    proxykey->dhlen = htons(dhlen);
    proxykey->siglen = htons(siglen);
    proxykey->hlen = (sizeof(struct proxy_key_h) + bloblen + dhlen + siglen)/4;

    meslen = sizeof(struct uftp_h) + (proxykey->hlen * 4);
    if (nb_sendto(listener, packet, meslen, 0, 
                  (struct sockaddr *)&pub_multi[0],
                  family_len(pub_multi[0])) == SOCKET_ERROR) {
        sockerror(0, 0, 0, "Error sending PROXY_KEY");
    } else {
        if ((rval = getnameinfo((struct sockaddr *)&pub_multi[0],
                family_len(pub_multi[0]), pubname, sizeof(pubname), NULL, 0,
                NI_NUMERICHOST)) != 0) {
            log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
        }
        log2(0, 0, 0, "Sent PROXY_KEY to %s", pubname);
    }
    free(packet);
}

/**
 * Sends an ABORT message upstream to a server
 */
void send_upstream_abort(struct pr_group_list_t *group, uint32_t addr,
                         const char *message)
{
    unsigned char *buf;
    struct uftp_h *header;
    struct abort_h *abort_hdr;
    int payloadlen;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    abort_hdr = (struct abort_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, ABORT, group);
    header->seq = group->send_seq_up++;
    header->src_id = uid;
    abort_hdr->func = ABORT;
    abort_hdr->hlen = sizeof(struct abort_h) / 4;
    abort_hdr->flags = 0;
    abort_hdr->host = addr;
    strncpy(abort_hdr->message, message, sizeof(abort_hdr->message) - 1);
    payloadlen = sizeof(struct uftp_h) + sizeof(struct abort_h);

    // Proxies should never need to send an encrypted ABORT

    if (nb_sendto(listener, buf, payloadlen, 0,
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending ABORT");
    }

    if (addr == 0) {
        group_cleanup(group);
    }
    free(buf);
}

/**
 * Sends an ABORT message downstream to clients
 */
void send_downstream_abort(struct pr_group_list_t *group, uint32_t dest_id,
                           const char *message, int current)
{
    unsigned char *buf;
    struct uftp_h *header;
    struct abort_h *abort_hdr;
    int payloadlen;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    abort_hdr = (struct abort_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, ABORT, group);
    header->seq = group->send_seq_down++;
    header->src_id = uid;
    abort_hdr->func = ABORT;
    abort_hdr->hlen = sizeof(struct abort_h) / 4;
    if ((dest_id == 0) && current) {
        abort_hdr->flags |= FLAG_CURRENT_FILE;
    }
    abort_hdr->host = dest_id;
    strncpy(abort_hdr->message, message, sizeof(abort_hdr->message) - 1);
    payloadlen = sizeof(struct uftp_h) + sizeof(struct abort_h);

    // Proxies should never need to send an encrypted ABORT

    if (nb_sendto(listener, buf, payloadlen, 0,
            (struct sockaddr *)&group->privatemcast,
            family_len(group->privatemcast)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending ABORT");
    }

    free(buf);
}

/**
 * Handles an ABORT message from a client or server
 * and forwards if necessary.
 */
void handle_abort(struct pr_group_list_t *group, const union sockaddr_u *src,
                  const unsigned char *message, unsigned meslen,
                  uint32_t src_id)
{
    const struct abort_h *abort_hdr;
    int upstream, hostidx, current;

    abort_hdr = (const struct abort_h *)message;

    upstream = (addr_equal(&group->up_addr, src));
    if (meslen < (abort_hdr->hlen * 4U) ||
            ((abort_hdr->hlen * 4U) < sizeof(struct abort_h))) {
        glog1(group, "Rejecting ABORT from %s: invalid message size",
                     upstream ? "server" : "client");
    }

    if (upstream) {
        if ((abort_hdr->host == 0) || abort_hdr->host == uid ) {
            glog1(group, "Transfer aborted by server: %s", abort_hdr->message);
            current = ((abort_hdr->flags & FLAG_CURRENT_FILE) != 0);
            if (proxy_type != RESPONSE_PROXY) {
                send_downstream_abort(group, 0, abort_hdr->message, current);
            }
            if (!current) {
                group_cleanup(group);
            }
        } else {
            if (proxy_type != RESPONSE_PROXY) {
                send_downstream_abort(group, abort_hdr->host,
                                      abort_hdr->message, 0);
            }
        }
    } else {
        if ((hostidx = find_client(group, src_id)) != -1) {
            glog1(group, "Transfer aborted by %s: %s",
                         group->destinfo[hostidx].name, abort_hdr->message);
        } else {
            glog1(group, "Transfer aborted by %08X: %s",
                         ntohl(src_id), abort_hdr->message);
        }
        send_upstream_abort(group, src_id, abort_hdr->message);
    }
}

/**
 * Verifies a server's or client's public key fingerprint
 * Returns 1 on success, 0 on failure
 */
int verify_fingerprint(const struct fp_list_t *fplist, int listlen,
                       const unsigned char *keyblob, uint16_t bloblen,
                       struct pr_group_list_t *group, uint32_t id)
{
    unsigned char fingerprint[HMAC_LEN];
    unsigned int fplen;
    int found, keyidx;

    if (listlen == 0) {
        return 1;
    }

    for (keyidx = 0, found = 0; (keyidx < listlen) && !found; keyidx++) {
        if (fplist[keyidx].uid == id) {
            keyidx--;
            found = 1;
        }
    }
    if (!found) {
        return 0;
    }
    if (!fplist[keyidx].has_fingerprint) {
        return 1;
    }

    hash(HASH_SHA1, keyblob, bloblen, fingerprint, &fplen);
    if (memcmp(fplist[keyidx].fingerprint, fingerprint, fplen)) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * Returns the verify_data string used in certain messages.  This value
 * is then run through the PRF with the result going into the message.
 */
uint8_t *build_verify_data(struct pr_group_list_t *group, int hostidx,
                           int *verifylen, int full)
{
    uint8_t *verifydata, *keyblob;
    uint32_t group_id;
    struct pr_destinfo_t *dest;
    union key_t key;
    int iplen;
    uint16_t bloblen;

    iplen = (group->privatemcast.ss.ss_family == AF_INET6) ?
            sizeof(struct in6_addr) : sizeof(struct in_addr);
    if (hostidx != -1) {
        dest = &group->destinfo[hostidx];
    }
    *verifylen = 0;
    if (!full) {
        verifydata = safe_calloc(sizeof(group->group_id) +
                iplen + sizeof(group->rand1) +
                sizeof(group->rand2) + sizeof(group->premaster), 1);
    } else {
        verifydata = safe_calloc(sizeof(group->group_id) +
                iplen + sizeof(group->rand1) +
                sizeof(group->rand2) + sizeof(group->premaster) +
                PUBKEY_LEN + sizeof(group->groupmaster), 1);
    }

    group_id = htonl(group->group_id);
    memcpy(verifydata, &group_id, sizeof(group_id));
    *verifylen += sizeof(group_id);
    if (group->privatemcast.ss.ss_family == AF_INET6) {
        memcpy(verifydata + *verifylen,
                &group->privatemcast.sin6.sin6_addr.s6_addr, iplen);
    } else {
        memcpy(verifydata + *verifylen,
                &group->privatemcast.sin.sin_addr.s_addr, iplen);
    }
    *verifylen += iplen;
    memcpy(verifydata + *verifylen, group->rand1, sizeof(group->rand1));
    *verifylen += sizeof(group->rand1);
    if (hostidx == -1) {
        memcpy(verifydata + *verifylen, group->rand2, sizeof(group->rand2));
        *verifylen += sizeof(group->rand2);
        memcpy(verifydata + *verifylen, group->premaster, group->premaster_len);
        *verifylen += group->premaster_len;
    } else {
        memcpy(verifydata + *verifylen, dest->rand2, sizeof(dest->rand2));
        *verifylen += sizeof(dest->rand2);
        memcpy(verifydata + *verifylen, dest->premaster, dest->premaster_len);
        *verifylen += dest->premaster_len;
    }

    if (full) {
        if (group->client_auth) {
            if (hostidx == -1) {
                key = group->proxy_privkey;
            } else {
                key = dest->pubkey;
            }
            keyblob = verifydata + *verifylen;
            if ((group->keyextype == KEYEX_RSA) ||
                    (group->keyextype == KEYEX_ECDH_RSA)) {
                if (!export_RSA_key(key.rsa, keyblob, &bloblen)) {
                    free(verifydata);
                    return NULL;
                }
            } else {
                if (!export_EC_key(key.ec, keyblob, &bloblen)) {
                    free(verifydata);
                    return NULL;
                }
            }
            *verifylen += bloblen;
        }
        memcpy(verifydata + *verifylen, group->groupmaster,
                sizeof(group->groupmaster));
        *verifylen += sizeof(group->groupmaster);
    }

    return verifydata;
}


