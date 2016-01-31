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

// none

#else  // if WINDOWS

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "server.h"
#include "server_common.h"

/**
 * Initializes the uftp header of an outgoing packet
 */
void set_uftp_header(struct uftp_h *header, int func, uint32_t group_id,
                     uint8_t group_inst, double l_grtt, int l_gsize)
{
    header->version = UFTP_VER_NUM;
    header->func = func;
    header->src_id = server_id;
    header->group_id = htonl(group_id);
    header->group_inst = group_inst;
    header->grtt = quantize_grtt(l_grtt);
    header->gsize = quantize_gsize(l_gsize);
}

/**
 * Sends an ABORT message to one or more clients
 */
void send_abort(const struct finfo_t *finfo, const char *message,
                const union sockaddr_u *destaddr,
                uint32_t dest, int encrypt, int current)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct abort_h *abort_hdr;
    int payloadlen, enclen;

    buf = safe_calloc(MAXMTU, 1);
    header = (struct uftp_h *)buf;
    abort_hdr = (struct abort_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, ABORT, finfo->group_id, finfo->group_inst,
                    grtt, destcount);
    header->seq = htons(send_seq++);
    abort_hdr->func = ABORT;
    abort_hdr->hlen = sizeof(struct abort_h) / 4;
    if (dest) {
        abort_hdr->host = dest;
    } else if (current) {
        abort_hdr->flags |= FLAG_CURRENT_FILE;
    }
    strncpy(abort_hdr->message, message, sizeof(abort_hdr->message) - 1);

    payloadlen = (abort_hdr->hlen * 4);
    if (encrypt) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen, keytype,
                groupkey, groupsalt, &ivctr, ivlen, hashtype, grouphmackey,
                hmaclen, sigtype, keyextype, privkey, privkeylen)) {
            glog0(finfo, "Error encrypting ABORT");
            free(buf);
            return;
        }
        outpacket = encrypted;
        payloadlen = enclen;
    } else {
        encrypted = NULL;
        outpacket = buf;
    }

    if (nb_sendto(sock, outpacket, payloadlen + sizeof(struct uftp_h), 0,
                  (const struct sockaddr *)destaddr,
                  family_len(*destaddr)) == SOCKET_ERROR) {
        gsockerror(finfo, "Error sending ABORT");
    }
    free(buf); 
    free(encrypted);
} 

/**
 * For messages that send a list of clients in the body, append all clients
 * in the specified state to the packet, then send the message of the given
 * type when either the body is full or the end of the client list has been
 * reached.  All header fields must be populated before calling.
 * Returns 1 on success, 0 on fail.
 */
int send_multiple(const struct finfo_t *finfo, unsigned char *packet,
                  int message, int attempt, uint32_t *idlist, int state,
                  int encrypt, const union sockaddr_u *destaddr, int regconf)
{
    struct uftp_h *header;
    int hsize, payloadlen, enclen, rval;
    int maxdest, packetcnt, dests, i;
    unsigned char *mheader, *encpacket, *outpacket;
    char out_addr[INET6_ADDRSTRLEN];

    header = (struct uftp_h *)packet;
    mheader = packet + sizeof(struct uftp_h);
    hsize = (unsigned char *)idlist - mheader;
    maxdest = blocksize / sizeof(uint32_t);
    packetcnt = 1;
    if (encrypt) {
        encpacket = safe_calloc(MAXMTU + keylen, 1); 
    } else {
        encpacket = NULL;
    }
    for (i = 0, dests = 0; i < destcount; i++) {
        if (message == REG_CONF) {
            // Only send REG_CONF for a particular client if either it's
            // behind a proxy or we're sending them to everyone.
            // Also, don't send if we already sent one and we haven't
            // gotten another REGISTER
            if ((destlist[i].status == state) &&
                    (!finfo->deststate[i].conf_sent) &&
                    (regconf || (destlist[i].proxyidx != -1))) {
                idlist[dests++] = destlist[i].id;
                finfo->deststate[i].conf_sent = 1;
            }
        } else if (message == DONE_CONF) {
            // As with REG_CONF, don't send a DONE_CONF for a client
            // if we already sent one and we haven't gotten another COMPLETE
            if ((destlist[i].status == state) &&
                    (!finfo->deststate[i].conf_sent)) {
                idlist[dests++] = destlist[i].id;
                finfo->deststate[i].conf_sent = 1;
            }
        } else if (destlist[i].status == state) {
            idlist[dests++] = destlist[i].id;
        }
        if ((dests >= maxdest) ||
                ((i == destcount - 1) && ((dests > 0) || (message == DONE)))) {
            header->seq = htons(send_seq++);
            payloadlen = hsize + (dests * sizeof(uint32_t));
            if (message == ANNOUNCE) {
                outpacket = packet;
                if (!sign_announce(finfo, outpacket, payloadlen)) {
                    glog0(finfo, "Error signing ANNOUNCE");
                    free(encpacket);
                    return 0;
                }
            } else if (encrypt) {
                if (!encrypt_and_sign(packet, &encpacket, payloadlen, &enclen,
                        keytype, groupkey, groupsalt, &ivctr, ivlen, hashtype,
                        grouphmackey, hmaclen, sigtype, keyextype,
                        privkey, privkeylen)) {
                    glog0(finfo, "Error encrypting %s", func_name(message));
                    free(encpacket);
                    return 0;
                }
                outpacket = encpacket;
                payloadlen = enclen;
            } else {
                outpacket = packet;
            }
            glog2(finfo, "Sending %s %d.%d", func_name(message), 
                         attempt, packetcnt);
            if (log_level >= 4) {
                rval = getnameinfo((const struct sockaddr *)destaddr,
                        family_len(*destaddr), out_addr, sizeof(out_addr),
                        NULL, 0, NI_NUMERICHOST);
                if (rval) {
                    glog4(finfo, "getnameinfo failed: %s", gai_strerror(rval));
                }
                glog4(finfo, "Sending to %s", out_addr);
            }
            if (nb_sendto(sock, outpacket, payloadlen + sizeof(struct uftp_h),
                          0, (const struct sockaddr *)destaddr,
                          family_len(*destaddr)) == SOCKET_ERROR) {
                gsockerror(finfo, "Error sending %s", func_name(message));
                sleep(1);
                free(encpacket);
                return 0;
            }
            if (packet_wait) usleep(packet_wait);
            memset(idlist, 0, maxdest * sizeof(uint32_t));
            dests = 0;
            packetcnt++;
        }
    }
    free(encpacket);
    return 1;
}

/**
 * Do basic checking on a received packet, like checking the version
 * and making sure the size matches the size in the header.
 * Returns 1 on success, 0 on fail.
 */
int validate_packet(const unsigned char *packet, int len,
                    const struct finfo_t *finfo)
{
    const struct uftp_h *header;

    header = (const struct uftp_h *)packet;
    if (header->version != UFTP_VER_NUM) {
        glog4(finfo, "Invalid version %02X", header->version);
        return 0;
    }
    if (header->func == ENCRYPTED) {
        if (len < sizeof(struct uftp_h) + sizeof(struct encrypted_h)) {
            glog4(finfo, "Invalid packet size %d", len);
            return 0;
        }
    } else {
        if (len < sizeof(struct uftp_h) + 4) {
            glog4(finfo, "Invalid packet size %d", len);
            return 0;
        }
    }
    if (ntohl(header->group_id) != finfo->group_id) {
        glog1(finfo, "Invalid group ID %08X, expected %08X",
                     ntohl(header->group_id), finfo->group_id);
        return 0;
    }
    if ((header->func == ENCRYPTED) && (keytype == KEY_NONE)) {
        glog1(finfo, "Received encrypted packet with encryption disabled");
        return 0;
    }
    return 1;
}

/**
 * Apply a signature to an ANNOUNCE if the key exchange scheme calls for it.
 * On entry, the packet should be complete other that the signature.
 * Returns 1 on success, 0 on fail.
 */
int sign_announce(const struct finfo_t *finfo, unsigned char *packet,
                  int packetlen)
{
    struct announce_h *announce;
    struct enc_info_he *encinfo;
    unsigned char *sig, *sigcopy;
    unsigned int iplen, siglen, _siglen;

    if ((keyextype != KEYEX_ECDH_RSA) && (keyextype != KEYEX_ECDH_ECDSA)) {
        return 1;
    }

    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    if (announce->flags & FLAG_IPV6) {
        iplen = sizeof(struct in6_addr);
    } else {
        iplen = sizeof(struct in_addr);
    }
    encinfo = (struct enc_info_he *)(packet + sizeof(struct uftp_h) +
                                     sizeof(struct announce_h) + iplen + iplen);
    sig = (unsigned char *)encinfo + sizeof(struct enc_info_he) +
            ntohs(encinfo->keylen) + ntohs(encinfo->dhlen);

    siglen = ntohs(encinfo->siglen);
    memset(sig, 0, siglen);
    sigcopy = safe_calloc(siglen, 1);

    if (keyextype == KEYEX_ECDH_ECDSA) {
        if (!create_ECDSA_sig(privkey.ec, hashtype, packet, packetlen,
                              sigcopy, &_siglen)) {
            // Called function should log
            free(sigcopy);
            return 0;
        }
    } else {
        if (!create_RSA_sig(privkey.rsa, hashtype, packet, packetlen,
                            sigcopy, &_siglen)) {
            // Called function should log
            free(sigcopy);
            return 0;
        }
    }
    if (_siglen != siglen) {
        glog0(finfo, "Signature length doesn't match expected length");
        glog1(finfo, "expected %d, got %d", siglen, _siglen);
        free(sigcopy);
        return 0;
    }
    memcpy(sig, sigcopy, siglen);
    free(sigcopy);
    return 1;
}

/**
 * Look for a given client in the global client list
 * Returns the client's index in the list, or -1 if not found
 */
int find_client(uint32_t id)
{
    int i;

    // TODO: This can be a lot more efficient.  Should probably sort by
    // ID and keep an index, then do a binary search.
    for (i = 0; i < destcount; i++) {
        if (destlist[i].id == id) {
            return i;
        }
    }
    return -1;
}

/**
 * Check to see if a client is in an error state
 * Returns 1 if true, 0 if false
 */
int client_error(int listidx)
{
    return ((destlist[listidx].status == DEST_MUTE) ||
            (destlist[listidx].status == DEST_LOST) ||
            (destlist[listidx].status == DEST_ABORT));
}

/**
 * Process an ABORT message
 */
void handle_abort(const unsigned char *message, int meslen, int idx,
                  struct finfo_t *finfo, uint32_t src)
{
    const struct abort_h *abort_hdr;
    int i;

    abort_hdr = (const struct abort_h *)message;
    if (meslen < (abort_hdr->hlen * 4)) {
        glog1(finfo, "Rejecting ABORT from %08X: invalid message size",
                     (idx == -1) ? ntohl(src) : destlist[idx].id);
        return;
    }
    if (idx == -1) {
        glog1(finfo, "Transfer aborted by %08X: %s",
                     ntohl(src), abort_hdr->message);
        return;
    }

    if (abort_hdr->host != 0) {
        idx = find_client(abort_hdr->host);
    }
    if (idx == -1) {
        glog1(finfo, "Transfer aborted by %08X: %s",
                     ntohl(src), abort_hdr->message);
    } else {
        destlist[idx].status = DEST_ABORT;
        glog1(finfo, "Transfer aborted by %s: %s",
                     destlist[idx].name, abort_hdr->message);
    }
    if (quit_on_error) {
        glog0(finfo, "Aborting all clients");
        send_abort(finfo, "A client aborted, aborting all",
                &receive_dest, 0, 0, 0);
        // If encryption enabled, send ABORT both encrypted and unencrypted
        // since we can't be sure what phase we're currently in.
        if (keytype != KEY_NONE) {
            send_abort(finfo, "A client aborted, aborting all",
                    &receive_dest, 0, 1, 0);
        }
        for (i = 0; i < destcount; i++) {
            if ((destlist[i].status == DEST_ACTIVE) ||
                    (destlist[i].status == DEST_REGISTERED)) {
                destlist[i].status = DEST_ABORT;
            }
        }
    }
}

/**
 * Recalculate the GRTT based on the RTTs of all receivers
 * Returns 1 if at least one active client is found, 0 if no active clients
 */
int recalculate_grtt(const struct finfo_t *finfo, int grtt_set,
                     int clear_measured)
{
    double new_grtt;
    int i, found;

    for (new_grtt = 0, found = 0, i = 0; i < destcount; i++) {
        if (!client_error(i) && destlist[i].rtt_measured) {
            found = 1;
            if (destlist[i].rtt > new_grtt) {
                new_grtt = destlist[i].rtt;
            }
        }
        if (clear_measured) {
            destlist[i].rtt_measured = 0;
        }
        destlist[i].rtt_sent = 0;
    }
    if (found) {
        if (new_grtt < min_grtt) {
            new_grtt = min_grtt;
        } else if (new_grtt > max_grtt) {
            new_grtt = max_grtt;
        }
        if (grtt_set && (new_grtt < 0.9 * grtt)) {
            grtt = 0.9 * grtt;
        } else {
            grtt = new_grtt;
        }
        glog3(finfo, "grtt = %.6f", grtt);
        return 1;
    } else {
        return 0;
    }
}
