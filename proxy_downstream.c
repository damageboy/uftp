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
#include <errno.h>

#ifdef WINDOWS

#include "win_func.h"

#else

#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_downstream.h"

/**
 * Adds a client to the given group
 */
int add_client(uint32_t id, struct pr_group_list_t *group)
{
    struct pr_destinfo_t *dest;

    dest = &group->destinfo[group->destcount];
    snprintf(dest->name, sizeof(dest->name), "0x%08X", ntohl(id));
    dest->id = id;
    dest->pending = -1;
    return group->destcount++;
}

/**
 * For a given client, calculate the master key and do key expansion
 * to determine the symmetric cypher key and IV salt, and hash key
 */
void calculate_client_keys(struct pr_group_list_t *group, int hostidx)
{
    unsigned char *seed, *prf_buf;
    int explen, len, seedlen;
    struct pr_destinfo_t *dest;

    dest = &group->destinfo[hostidx];

    explen = group->keylen + group->ivlen +
             group->hmaclen;
    seedlen = sizeof(group->rand1) * 2;
    seed = safe_calloc(seedlen, 1);
    prf_buf = safe_calloc(MASTER_LEN + explen + group->hmaclen, 1);

    memcpy(seed, group->rand1, sizeof(group->rand1));
    memcpy(seed + sizeof(group->rand1), dest->rand2,
            sizeof(dest->rand2));
    PRF(group->hashtype, MASTER_LEN, dest->premaster, dest->premaster_len,
            "master secret", seed, seedlen, prf_buf, &len);
    memcpy(dest->master,prf_buf, sizeof(dest->master));

    PRF(group->hashtype, explen, dest->master, sizeof(dest->master),
            "key expansion", seed, seedlen, prf_buf, &len);
    memcpy(dest->hmackey, prf_buf, group->hmaclen);
    memcpy(dest->key, prf_buf + group->hmaclen, group->keylen);
    memcpy(dest->salt, prf_buf + group->hmaclen + group->keylen, group->ivlen);

    free(seed);
    free(prf_buf);
}

/**
 * Verifies the data in a CLIENT_KEY message signed by the client's public key
 */
int verify_client_key(struct pr_group_list_t *group, int hostidx)
{
    uint8_t *verifydata;
    int verifylen;
    struct pr_destinfo_t *dest;

    dest = &group->destinfo[hostidx];

    // build_verify_data should never fail in this case
    verifydata = build_verify_data(group, hostidx, &verifylen, 0);

    if ((group->keyextype == KEYEX_RSA) ||
            (group->keyextype == KEYEX_ECDH_RSA)) {
        if (!verify_RSA_sig(dest->pubkey.rsa, group->hashtype, verifydata,
                verifylen, dest->verifydata, dest->verifylen)) {
            glog1(group, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                         dest->name);
            free(verifydata);
            return 0;
        }
    } else {
        if (!verify_ECDSA_sig(dest->pubkey.ec, group->hashtype, verifydata,
                verifylen, dest->verifydata, dest->verifylen)) {
            glog1(group, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                         dest->name);
            free(verifydata);
            return 0;
        }
    }

    free(verifydata);
    return 1;
}

/**
 * Processes encryption key information received in a REGISTER message
 */
int handle_register_keys(const struct register_h *reg,
                         const unsigned char *enckey,
                         struct pr_group_list_t *group, int hostidx,
                         uint32_t src)
{
    unsigned char premaster[PUBKEY_LEN];
    unsigned int len;
    struct pr_destinfo_t *dest;

    dest = &group->destinfo[hostidx];
    memcpy(dest->rand2, reg->rand2, sizeof(dest->rand2));
    if (group->keyextype == KEYEX_RSA) {
        if (!RSA_decrypt(group->proxy_privkey.rsa, enckey,
                         ntohs(reg->keyinfo_len), premaster, &len)) {
            glog1(group, "Rejecting REGISTER from %s: "
                         "failed to decrypt premaster secret", dest->name);
            return 0;
        }
        if (len != MASTER_LEN) {
            glog1(group, "Rejecting REGISTER from %s: "
                         "premaster secret wrong length", dest->name);
            return 0;
        }
    } else {
        if (!import_EC_key(&dest->dhkey.ec, enckey,
                           ntohs(reg->keyinfo_len), 1)) {
            glog1(group, "Rejecting REGISTER from %s: "
                         "failed to import ECDH key", dest->name);
            return 0;
        }
        if (get_EC_curve(dest->dhkey.ec) !=
                get_EC_curve(group->proxy_dhkey.ec)) {
            glog1(group, "Rejecting REGISTER from %s: "
                         "invalid curve for ECDH", dest->name);
            return 0;
        }
        if (!get_ECDH_key(dest->dhkey.ec, group->proxy_dhkey.ec,
                          premaster, &len)) {
            glog1(group, "Rejecting REGISTER from %s: "
                         "failed to calculate premaster secret", dest->name);
            return 0;
        }

    }
    memcpy(dest->premaster, premaster, len);
    dest->premaster_len = len;
    calculate_client_keys(group, hostidx);

    if (dest->pubkey.key) {
        if (!verify_client_key(group, hostidx)) {
            return 0;
        }
    }

    return 1;
}

/**
 * Handles an incoming REGSITER message from a client.
 */
void handle_register(struct pr_group_list_t *group, int hostidx,
                     const unsigned char *message, unsigned meslen,
                     uint32_t src)
{
    const struct register_h *reg;
    const unsigned char *enckey;
    struct pr_destinfo_t *dest;
    int dupmsg;

    reg = (const struct register_h *)message;
    enckey = (const unsigned char *)reg + sizeof(struct register_h);

    if (group->destcount == MAXPROXYDEST) {
        glog1(group, "Rejecting REGISTER from %08X: max destinations exceeded",
                     ntohl(src));
        send_downstream_abort(group, src, "Max destinations exceeded", 0);
        return;
    }
    if ((meslen < (reg->hlen * 4U)) || ((reg->hlen * 4U) <
            sizeof(struct register_h) + ntohs(reg->keyinfo_len))) {
        glog1(group, "Rejecting REGISTER from %08X: invalid message size",
                     ntohl(src));
        send_downstream_abort(group, src, "Invalid message size", 0);
        return;
    }

    if (hostidx == -1) {
        hostidx = add_client(src, group);
    }
    dest = &group->destinfo[hostidx];
    dupmsg = (dest->registered == 1);
    dest->registered = 1;
    dest->regtime.tv_sec = ntohl(reg->tstamp_sec);
    dest->regtime.tv_usec = ntohl(reg->tstamp_usec);

    if (dest->state != PR_CLIENT_REGISTERED) {
        if (group->keytype != KEY_NONE) {
            if (!handle_register_keys(reg, enckey, group, hostidx, src)) {
                return;
            }
        }
        if (!group->client_auth || dest->pubkey.key) {
            dest->state = PR_CLIENT_REGISTERED;
        }
    }

    glog2(group, "Received REGISTER%s from %s", dupmsg ? "+" : "", dest->name);

    if (dest->state == PR_CLIENT_REGISTERED) {
        check_pending(group, hostidx, message);
    }
}

/**
 * Handles an incoming CLIENT_KEY message from a client.
 */
void handle_clientkey(struct pr_group_list_t *group, int hostidx,
                      const unsigned char *message, unsigned meslen,
                      uint32_t src)
{
    const struct client_key_h *clientkey;
    const unsigned char *keyblob, *verify;
    struct pr_destinfo_t *dest;
    int dupmsg;

    clientkey = (const struct client_key_h *)message;
    keyblob = (const unsigned char *)clientkey + sizeof(struct client_key_h);
    verify = keyblob + ntohs(clientkey->bloblen);

    if (group->destcount == MAXPROXYDEST) {
        glog1(group, "Rejecting CLIENT_KEY from %08X: "
                     "max destinations exceeded", ntohl(src));
        send_downstream_abort(group, src, "Max destinations exceeded", 0);
        return;
    }
    if ((meslen < (clientkey->hlen * 4U)) ||
            ((clientkey->hlen * 4U) < sizeof(struct client_key_h) +
                ntohs(clientkey->bloblen) + ntohs(clientkey->siglen))) {
        glog1(group, "Rejecting CLIENT_KEY from %08X: invalid message size",
                     ntohl(src));
        send_downstream_abort(group, src, "Invalid message size", 0);
        return;
    }
    if ((((group->keyextype == KEYEX_RSA) ||
                    (group->keyextype == KEYEX_ECDH_RSA)) &&
                (keyblob[0] != KEYBLOB_RSA)) ||
            ((group->keyextype == KEYEX_ECDH_ECDSA) &&
             (keyblob[0] != KEYBLOB_EC))) {
        glog1(group, "Rejecting CLIENT_KEY from %08X: invalid keyblob type",
                     ntohl(src));
        send_downstream_abort(group, src, "Invalid keyblob type", 0);
        return;
    }


    if (hostidx == -1) {
        hostidx = add_client(src, group);
    }
    dest = &group->destinfo[hostidx];
    dupmsg = (dest->pubkey.key != 0);

    if (!dest->verified) {
        if (keyblob[0] == KEYBLOB_RSA) {
            if (!import_RSA_key(&dest->pubkey.rsa, keyblob,
                                ntohs(clientkey->bloblen))) {
                glog1(group, "Failed to load client public key");
                send_downstream_abort(group, src,
                                      "Failed to load client public key", 0);
                return;
            }
            dest->pubkeylen = RSA_keylen(dest->pubkey.rsa);
        } else {
            if (!import_EC_key(&dest->pubkey.ec, keyblob,
                               ntohs(clientkey->bloblen), 0)) {
                glog1(group, "Failed to load client public key");
                send_downstream_abort(group, src,
                                      "Failed to load client public key", 0);
                return;
            }
            dest->pubkeylen = ECDSA_siglen(dest->pubkey.ec);
        }
        if (!verify_fingerprint(client_fp, client_fp_count, keyblob,
                                ntohs(clientkey->bloblen), group, src)) {
            glog1(group, "Failed to verify client key fingerprint");
            send_downstream_abort(group, src, 
                                  "Failed to verify client key fingerprint", 0);
            return;
        }
        dest->verified = 1;
    }

    memcpy(dest->verifydata, verify, ntohs(clientkey->siglen));
    dest->verifylen = ntohs(clientkey->siglen);
    if (dest->registered) {
        if (!verify_client_key(group, hostidx)) {
            return;
        }
        dest->state = PR_CLIENT_REGISTERED;
    }

    glog2(group,"Received CLIENT_KEY%s from %s", dupmsg ? "+" : "", dest->name);

    if (dest->state == PR_CLIENT_REGISTERED) {
        // Pass in a dummy REGISTER message to check_pending, since
        // CLIENT_KEY is basically an extension of REGISTER.
        struct register_h reg;
        reg.func = REGISTER;
        check_pending(group, hostidx, (unsigned char *)&reg);
    }
}

/**
 * Handles an incoming KEYINFO_ACK message from a client
 */
void handle_keyinfo_ack(struct pr_group_list_t *group, int hostidx,
                        const unsigned char *message, unsigned meslen)
{
    const struct keyinfoack_h *keyinfoack;
    unsigned char *verifydata, *verify_hash, *verify_test;
    int verifylen, len, dupmsg;
    unsigned int hashlen;
    struct pr_destinfo_t *dest;

    keyinfoack = (const struct keyinfoack_h *)message;
    dest = &group->destinfo[hostidx];

    if ((meslen < (keyinfoack->hlen * 4U)) ||
            ((keyinfoack->hlen * 4U) < sizeof(struct keyinfoack_h))) {
        glog1(group, "Rejecting KEYINFO_ACK from %s: invalid message size",
                     dest->name);
        send_downstream_abort(group, dest->id, "Invalid message size", 0);
        return;
    }

    if (!(verifydata = build_verify_data(group, hostidx, &verifylen,1))) {
        glog1(group, "Rejecting KEYINFO_ACK from %s: "
                     "error exporting client public key", dest->name);
        return;
    }
    verify_hash = safe_calloc(group->hmaclen, 1);
    verify_test = safe_calloc(VERIFY_LEN + group->hmaclen, 1);
    hash(group->hashtype, verifydata, verifylen, verify_hash, &hashlen);
    PRF(group->hashtype, VERIFY_LEN, group->groupmaster,
            sizeof(group->groupmaster), "client finished",
            verify_hash, hashlen, verify_test, &len);
    if (memcmp(keyinfoack->verify_data, verify_test, VERIFY_LEN)) {
        glog1(group, "Rejecting KEYINFO_ACK from %s: verify data mismatch",
                     dest->name);
        free(verifydata);
        free(verify_hash);
        free(verify_test);
        return;
    }

    free(verifydata);
    free(verify_hash);
    free(verify_test);

    dupmsg = (dest->state == PR_CLIENT_READY);
    glog2(group, "Received KEYINFO_ACK%s from %s", dupmsg ? "+" : "",
                 dest->name);
    dest->state = PR_CLIENT_READY;
    if (!check_unfinished_clients(group, 0)) {
        group->phase = PR_PHASE_RECEIVING;
    }
}

/**
 * Handles an incoming FILEINFO_ACK message from a client
 */
void handle_fileinfo_ack(struct pr_group_list_t *group, int hostidx,
                         const unsigned char *message, unsigned meslen)
{
    const struct fileinfoack_h *fileinfoack;
    struct pr_destinfo_t *dest;

    fileinfoack = (const struct fileinfoack_h *)message;
    dest = &group->destinfo[hostidx];

    if ((meslen < (fileinfoack->hlen * 4U)) ||
            ((fileinfoack->hlen * 4U) < sizeof(struct fileinfoack_h))) {
        log1(group->group_id, group->group_inst, ntohs(fileinfoack->file_id),
                "Rejecting FILEINFO_ACK from %s: invalid message size",
                dest->name);
        return;
    }

    log2(group->group_id, group->group_inst, ntohs(fileinfoack->file_id),
            "Received FILEINFO_ACK from %s", dest->name);
    check_pending(group, hostidx, message);
}

/**
 * Sends a KEYINFO to each client that the server sent a REG_CONF for.
 */
void send_keyinfo(struct pr_group_list_t *group, const uint32_t *addrlist,
                  int addrlen)
{
    unsigned char *buf, *iv;
    struct uftp_h *header;
    struct keyinfo_h *keyinfo_hdr;
    struct destkey *keylist;
    unsigned int payloadlen, len;
    int maxdest, packetcnt, dests, iv_init, foundaddr, i, j;
    int unauth_keytype, unauth_keylen, unauth_ivlen;
    struct pr_destinfo_t *dest;

    // Don't use a cipher in an authentication mode to encrypt the group master
    unauth_keytype = unauth_key(group->keytype);
    get_key_info(unauth_keytype, &unauth_keylen, &unauth_ivlen);

    buf = safe_calloc(MAXMTU, 1);
    iv = safe_calloc(unauth_ivlen, 1);
    header = (struct uftp_h *)buf;
    keyinfo_hdr = (struct keyinfo_h *)(buf + sizeof(struct uftp_h));
    keylist= (struct destkey *)((char *)keyinfo_hdr + sizeof(struct keyinfo_h));

    set_uftp_header(header, KEYINFO, group);
    keyinfo_hdr->func = KEYINFO;
    keyinfo_hdr->hlen = sizeof(struct keyinfo_h) / 4;

    iv_init = 0;
    maxdest = max_msg_dest(group, KEYINFO, keyinfo_hdr->hlen * 4);
    packetcnt = 1;
    for (i = 0, dests = 0; i < group->destcount; i++) {
        dest = &group->destinfo[i];
        if (dest->state == PR_CLIENT_CONF) {
            if (addrlist) {
                // We just got a REG_CONF, so only send to listed hosts
                for (j = 0, foundaddr = 0; (j < addrlen) && (!foundaddr); j++) {
                    if (dest->id == addrlist[j]) {
                        foundaddr = 1;
                    }
                }
            } else {
                foundaddr = 1;
            }
            if (foundaddr) {
                if (!iv_init) {
                    group->ivctr++;
                    keyinfo_hdr->iv_ctr_hi =
                            htonl((group->ivctr & 0xFFFFFFFF00000000LL) >> 32);
                    keyinfo_hdr->iv_ctr_lo =
                            htonl(group->ivctr & 0x00000000FFFFFFFFLL);
                    iv_init = 1;
                }
                keylist[dests].dest_id = dest->id;
                build_iv(iv, dest->salt, unauth_ivlen,
                         uftp_htonll(group->ivctr), group->src_id);
                if (!encrypt_block(unauth_keytype, iv, dest->key,
                                   NULL, 0, &group->groupmaster[1],
                                   sizeof(group->groupmaster) - 1,
                                   keylist[dests].groupmaster, &len)) {
                    glog0(group, "Error encrypting KEYINFO for %s", dest->name);
                    free(buf);
                    free(iv);
                    return;
                }
                dests++;
            }
        }
        if ((dests >= maxdest) ||
                ((i == group->destcount - 1) && (dests > 0))) {
            payloadlen = sizeof(struct keyinfo_h) +
                         (dests * sizeof(struct destkey));
            glog2(group,"Sending KEYINFO %d.%d", group->keyinfo_cnt, packetcnt);
            if (nb_sendto(listener, buf, payloadlen + sizeof(struct uftp_h), 0,
                       (struct sockaddr *)&group->privatemcast,
                        family_len(group->privatemcast)) == SOCKET_ERROR) {
                gsockerror(group, "Error sending KEYINFO");
                free(buf);
                free(iv);
                return;
            }
            // TODO: This value is good for around 100Mbps.  This is under the
            // assumption that the client proxy is local to the clients
            // it serves.  This should probably be a parameter.
            usleep(120);
            memset(keylist, 0, maxdest * sizeof(struct destkey));
            iv_init = 0;
            dests = 0;
            packetcnt++;
        }
    }
    group->keyinfo_cnt++;
    set_timeout(group, 0, 0);
    free(buf);
    free(iv);
}

/**
 * Handles an incoming STATUS message from a client
 */
void handle_status(struct pr_group_list_t *group, int hostidx,
                   const unsigned char *message, unsigned meslen)
{
    const struct status_h *status;
    int mes_section;
    struct pr_destinfo_t *dest;

    status = (const struct status_h *)message;
    mes_section = ntohs(status->section);
    dest = &group->destinfo[hostidx];

    if ((meslen < (status->hlen * 4U)) ||
            ((status->hlen * 4U) < sizeof(struct status_h))) {
        log1(group->group_id, group->group_inst, ntohs(status->file_id),
                "Rejecting STATUS from %s: invalid message size", dest->name);
        return;
    }

    log2(group->group_id, group->group_inst, ntohs(status->file_id),
            "Got STATUS for section %d from %s", mes_section, dest->name);

    check_pending(group, hostidx, message);
}

/**
 * Handles an incoming COMPLETE message from a client
 */
void handle_complete(struct pr_group_list_t *group, int hostidx,
                     const unsigned char *message, unsigned meslen)
{
    const struct complete_h *complete;
    struct pr_destinfo_t *dest;
    int alldone, i;
    char status[20];

    complete = (const struct complete_h *)message;
    dest = &group->destinfo[hostidx];

    if ((meslen < (complete->hlen * 4U)) ||
            ((complete->hlen * 4U) < sizeof(struct complete_h))) {
        log1(group->group_id, group->group_inst, ntohs(complete->file_id),
                "Rejecting COMPLETE from %s: invalid message size", dest->name);
        return;
    }

    switch (complete->status) {
    case COMP_STAT_NORMAL:
        strncpy(status, "", sizeof(status));
        break;
    case COMP_STAT_SKIPPED:
        strncpy(status, "(skipped)", sizeof(status));
        break;
    case COMP_STAT_OVERWRITE:
        strncpy(status, "(overwritten)", sizeof(status));
        break;
    case COMP_STAT_REJECTED:
        strncpy(status, "(rejected)", sizeof(status));
        break;
    }
    log2(group->group_id, group->group_inst, ntohs(complete->file_id),
            "Received COMPLETE%s from %s", status, dest->name);

    if (ntohs(complete->file_id) == 0) {
        dest->state = PR_CLIENT_DONE;
        for (alldone = 1, i = 0;
                (i < group->destcount) && alldone; i++) {
            alldone = alldone && (group->destinfo[i].state == PR_CLIENT_DONE);
        }
        if (alldone) {
            group->phase = PR_PHASE_DONE;
        }
    }

    check_pending(group, hostidx, message);
}

