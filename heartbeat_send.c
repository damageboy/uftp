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
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "uftp_common.h"
#include "heartbeat_send.h"

/**
 * Process an HB_RESP message
 */
void handle_hb_response(SOCKET s, const union sockaddr_u *src,
                        const unsigned char *message, unsigned meslen,
                        union sockaddr_u hb_hosts[], int num_hosts,
                        union key_t privkey, int keytype, uint32_t uid)
{
    const struct hb_resp_h *hbresp;
    char addrname[INET6_ADDRSTRLEN];
    int hostidx, rval;

    hbresp = (const struct hb_resp_h *)message;

    if (meslen < (hbresp->hlen * 4U) ||
            ((hbresp->hlen * 4U) < sizeof(struct hb_resp_h))) {
        log1(0, 0, 0, "Rejecting HB_RESP: invalid message size");
        return;
    }

    if ((rval = getnameinfo((const struct sockaddr *)src,
            sizeof(union sockaddr_u), addrname, sizeof(addrname),
            NULL, 0, NI_NUMERICHOST)) != 0) {
        log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
    }
    log2(0, 0, 0, "Received HB_RESP from %s", addrname);
    if (hbresp->authenticated == HB_AUTH_CHALLENGE) {
        log1(0, 0, 0, "Heartbeat authentication required");
        for (hostidx = 0; hostidx < num_hosts; hostidx++) {
            if (addr_equal(src, &hb_hosts[hostidx])) {
                send_auth_hb_request(s, &hb_hosts[hostidx],
                        ntohl(hbresp->nonce), privkey, keytype, uid);
                break;
            }
        }
    } else if (hbresp->authenticated == HB_AUTH_FAILED) {
        log1(0, 0, 0, "Heartbeat authentication failed");
    } else if (hbresp->authenticated == HB_AUTH_OK) {
        log2(0, 0, 0, "Heartbeat authentication successful");
    }
}

/**
 * Sends an authenticated HB_REQ message to the given host.
 */
void send_auth_hb_request(SOCKET s, union sockaddr_u *hbhost, uint32_t nonce,
                          union key_t privkey, int keytype, uint32_t uid)
{
    unsigned char *packet, *keyblob, *sig;
    struct uftp_h *header;
    struct hb_req_h *hbreq;
    uint32_t n_nonce;
    unsigned int meslen, siglen, rval;
    uint16_t bloblen;
    char addrname[INET6_ADDRSTRLEN], portstr[PORTNAME_LEN];

    packet = safe_calloc(sizeof(struct uftp_h) + sizeof(struct hb_req_h) +
                    (PUBKEY_LEN * 2) , 1);

    header = (struct uftp_h *)packet;
    hbreq = (struct hb_req_h *)(packet + sizeof(struct uftp_h));
    keyblob = (unsigned char *)hbreq + sizeof(struct hb_req_h);
    header->version = UFTP_VER_NUM;
    header->func = HB_REQ;
    header->src_id = uid;
    hbreq->func = HB_REQ;
    n_nonce = htonl(nonce);
    hbreq->nonce = n_nonce;

    if (keytype == KEYBLOB_RSA) {
        if (!export_RSA_key(privkey.rsa, keyblob, &bloblen)) {
            log0(0, 0, 0, "Error exporting public key");
            free(packet);
            return;
        }
        sig = keyblob + bloblen;
        if (!create_RSA_sig(privkey.rsa, HASH_SHA1, (unsigned char *)&n_nonce,
                            sizeof(n_nonce), sig, &siglen)) {
            log0(0, 0, 0, "Error signing nonce");
            free(packet);
            return;
        }
    } else {
        if (!export_EC_key(privkey.ec, keyblob, &bloblen)) {
            log0(0, 0, 0, "Error exporting public key");
            free(packet);
            return;
        }
        sig = keyblob + bloblen;
        if (!create_ECDSA_sig(privkey.ec, HASH_SHA1, (unsigned char *)&n_nonce,
                              sizeof(n_nonce), sig, &siglen)) {
            log0(0, 0, 0, "Error signing nonce");
            free(packet);
            return;
        }
    }
    hbreq->bloblen = htons(bloblen);
    hbreq->siglen = htons(siglen);
    hbreq->hlen = (sizeof(struct hb_req_h) + bloblen + siglen) / 4;
    meslen = sizeof(struct uftp_h) + (hbreq->hlen * 4);
    if (nb_sendto(s, packet, meslen, 0, (struct sockaddr *)hbhost,
                  family_len(*hbhost)) == SOCKET_ERROR) {
        sockerror(0, 0, 0, "Error sending HB_REQ");
    } else {
        if ((rval = getnameinfo((struct sockaddr *)hbhost,
                sizeof(union sockaddr_u), addrname, sizeof(addrname), portstr,
                sizeof(portstr), NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
            log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
        }
        log2(0, 0, 0, "Sent authenticated HB_REQ to %s:%s", addrname, portstr);
    }
    free(packet);
}

/**
 * Sends an HB_REQ message to each host listed in the hb_host list
 */
void send_hb_request(SOCKET s, union sockaddr_u hb_hosts[], int num_hosts,
                     struct timeval *next_hb_time, int hb_interval,
                     uint32_t uid)
{
    unsigned char *packet;
    struct uftp_h *header;
    struct hb_req_h *hbreq;
    char addrname[INET6_ADDRSTRLEN], portstr[PORTNAME_LEN];
    int meslen, rval, i;

    packet = safe_calloc(sizeof(struct uftp_h) + sizeof(struct hb_req_h), 1);

    header = (struct uftp_h *)packet;
    hbreq = (struct hb_req_h *)(packet + sizeof(struct uftp_h));
    header->version = UFTP_VER_NUM;
    header->func = HB_REQ;
    header->src_id = uid;
    hbreq->func = HB_REQ;
    hbreq->hlen = sizeof(struct hb_req_h) / 4;

    for (i = 0; i < num_hosts; i++) {
        hbreq->nonce = 0;
        hbreq->bloblen = 0;
        hbreq->siglen = 0;
        meslen = sizeof(struct uftp_h) + (hbreq->hlen * 4);
        if (nb_sendto(s, packet, meslen, 0, (struct sockaddr *)&hb_hosts[i],
                      family_len(hb_hosts[i])) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error sending HB_REQ");
        } else {
            if ((rval = getnameinfo((struct sockaddr *)&hb_hosts[i],
                    sizeof(union sockaddr_u), addrname, sizeof(addrname),
                    portstr, sizeof(portstr),
                    NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
                log1(0, 0, 0, "getnameinfo failed: %s", gai_strerror(rval));
            }
            log2(0, 0, 0, "Sent HB_REQ to %s:%s", addrname, portstr);
        }
    }
    free(packet);
    gettimeofday(next_hb_time, NULL);
    next_hb_time->tv_sec += hb_interval;
}

