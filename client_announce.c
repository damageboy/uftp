/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2013   Dennis A. Bush, Jr.   bush@tcnj.edu
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

#include <ws2tcpip.h>
#include <io.h>
#include <direct.h>

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "client.h"
#include "client_common.h"
#include "client_announce.h"
#include "client_transfer.h"

/**
 * Finds next open slot in the global group list.
 * Returns a pointer to the open slot, or NULL if none found.
 */
struct group_list_t *find_open_slot()
{
    int i;

    for (i = 0; i < MAXLIST; i++) {
        if (group_list[i].group_id == 0) {
            memset(&group_list[i], 0, sizeof(group_list[i]));
            return &group_list[i];
        }
    }
    return NULL;
}

/**
 * Returns the verify_data string used in certain messages.  This value
 * is then run through the PRF with the result going into the message.
 */
uint8_t *build_verify_data(struct group_list_t *group, int *verifylen)
{
    uint8_t *verifydata;
    uint32_t group_id;
    int iplen;

    iplen = (group->multi.ss.ss_family == AF_INET6) ?
            sizeof(struct in6_addr) : sizeof(struct in_addr);
    *verifylen = 0;
    if (group->phase == PHASE_REGISTERED) {
        verifydata = calloc(sizeof(group->group_id) +
                iplen + sizeof(group->rand1) +
                sizeof(group->rand2) + sizeof(group->premaster), 1);
    } else {
        verifydata = calloc(sizeof(group->group_id) +
                iplen + sizeof(group->rand1) +
                sizeof(group->rand2) + sizeof(group->premaster) +
                PUBKEY_LEN + sizeof(group->groupmaster), 1);
    }
    if (verifydata == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    group_id = htonl(group->group_id);
    memcpy(verifydata, &group_id, sizeof(group_id));
    *verifylen += sizeof(group_id);
    if (group->multi.ss.ss_family == AF_INET6) {
        memcpy(verifydata + *verifylen, &group->multi.sin6.sin6_addr.s6_addr,
                iplen);
    } else {
        memcpy(verifydata + *verifylen, &group->multi.sin.sin_addr.s_addr,
                iplen);
    }
    *verifylen += iplen;
    memcpy(verifydata + *verifylen, group->rand1, sizeof(group->rand1));
    *verifylen += sizeof(group->rand1);
    memcpy(verifydata + *verifylen, group->rand2, sizeof(group->rand2));
    *verifylen += sizeof(group->rand2);
    memcpy(verifydata + *verifylen, group->premaster, group->premaster_len);
    *verifylen += group->premaster_len;

    if (group->phase != PHASE_REGISTERED) {
        if (group->client_auth) {
            uint16_t bloblen;
            uint8_t *keyblob = verifydata + *verifylen;

            if ((group->keyextype == KEYEX_RSA) ||
                    (group->keyextype == KEYEX_ECDH_RSA)) {
                if (!export_RSA_key(group->client_privkey.rsa,
                                    keyblob, &bloblen)) {
                    free(verifydata);
                    return NULL;
                }
            } else {
                if (!export_EC_key(group->client_privkey.ec,
                                   keyblob, &bloblen)) {
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

/**
 * Sends a CLIENT_KEY message if the server requested it.
 * Always sent right after a REGISTER.
 */
void send_client_key(struct group_list_t *group)
{
    struct uftp_h *header;
    struct client_key_h *client_key;
    unsigned char *buf, *keyblob, *verify;
    uint8_t *verifydata;
    unsigned int siglen, meslen;
    int verifylen;
    uint16_t bloblen;

    buf = calloc(MAXMTU, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    client_key = (struct client_key_h *)(buf + sizeof(struct uftp_h));
    keyblob = (unsigned char *)client_key + sizeof(struct client_key_h);

    verifydata = build_verify_data(group, &verifylen);
    if (!verifydata) {
        log0(group->group_id, group->file_id, "Error getting verify data");
        send_abort(group, "Error getting verify data");
        goto end;
    }

    set_uftp_header(header, CLIENT_KEY, group);

    client_key->func = CLIENT_KEY;
    if ((group->keyextype == KEYEX_RSA) ||
            (group->keyextype == KEYEX_ECDH_RSA)) {
        if (!export_RSA_key(group->client_privkey.rsa, keyblob, &bloblen)) {
            log0(group->group_id, group->file_id, "Error exporting public key");
            send_abort(group, "Error exporting public key");
            goto end;
        }
        verify = keyblob + bloblen;
        if (!create_RSA_sig(group->client_privkey.rsa, group->hashtype,
                            verifydata, verifylen, verify, &siglen)) {
            log0(group->group_id, group->file_id, "Error signing verify data");
            send_abort(group, "Error signing verify data");
            goto end;
        }
    } else {
        if (!export_EC_key(group->client_privkey.ec, keyblob, &bloblen)) {
            log0(group->group_id, group->file_id, "Error exporting public key");
            send_abort(group, "Error exporting public key");
            goto end;
        }
        verify = keyblob + bloblen;
        if (!create_ECDSA_sig(group->client_privkey.ec, group->hashtype,
                              verifydata, verifylen, verify, &siglen)) {
            log0(group->group_id, group->file_id, "Error signing verify data");
            send_abort(group, "Error signing verify data");
            goto end;
        }
    }

    client_key->bloblen = htons(bloblen);
    client_key->siglen = htons(siglen);
    client_key->hlen = (sizeof(struct client_key_h) + bloblen + siglen) / 4;

    meslen = sizeof(struct uftp_h) + (client_key->hlen * 4);
    if (nb_sendto(listener, buf, meslen, 0,
               (struct sockaddr *)&(group->replyaddr),
               family_len(group->replyaddr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->file_id, "Error sending CLIENT_KEY");
    } else {
        log2(group->group_id, group->file_id, "CLIENT_KEY sent");
    }

end:
    free(verifydata);
    free(buf);
}

/**
 * Sends a REGISTER message in response to an ANNOUNCE or on timeout when
 * waiting for a KEYINFO or REG_CONF.  If the register timeout expired, abort.
 */
void send_register(struct group_list_t *group)
{
    struct uftp_h *header;
    struct register_h *reg;
    unsigned char *buf, *keyinfo;
    struct timeval now, send_time;
    unsigned int len, meslen;
    union key_t key;

    gettimeofday(&now, NULL);
    if (cmptimestamp(now, group->expire_time) >= 0) {
        log1(group->group_id, group->file_id,
                "Registration unconfirmed by server");
        send_abort(group, "Registration unconfirmed");
        return;
    }

    buf = calloc(MAXMTU, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    reg = (struct register_h *)(buf + sizeof(struct uftp_h));
    keyinfo = (unsigned char *)reg + sizeof(struct register_h);
    set_uftp_header(header, REGISTER, group);
    reg->func = REGISTER;
    if (group->keytype != KEY_NONE) {
        memcpy(reg->rand2, group->rand2, RAND_LEN);
        if (group->keyextype == KEYEX_RSA) {
            if (has_proxy) {
                key = proxy_pubkey;
            } else {
                key = group->server_pubkey;
            }
            if (!RSA_encrypt(key.rsa, group->premaster, group->premaster_len,
                             keyinfo, &len)) {
                log0(group->group_id, group->file_id,
                        "Error encrypting premaster secret");
                send_abort(group, "Error encrypting premaster secret");
                free(buf);
                return;
            }
        } else {
            uint16_t keylen;
            if (!export_EC_key(group->client_dhkey.ec, keyinfo, &keylen)) {
                log0(group->group_id, group->file_id,
                        "Error exporting ECDH public key");
                send_abort(group, "Error exporting ECDH public key");
                free(buf);
                return;
            }
            len = keylen;
        }
        reg->keyinfo_len = htons(len); 
    } else {
        len = 0;
    }
    gettimeofday(&now, NULL);
    if (cmptimestamp(now, group->last_server_rx_ts) <= 0) {
        send_time = group->last_server_ts;
    } else {
        send_time = add_timeval(group->last_server_ts,
                diff_timeval(now, group->last_server_rx_ts));
    }
    reg->tstamp_sec = htonl((uint32_t)send_time.tv_sec);
    reg->tstamp_usec = htonl((uint32_t)send_time.tv_usec);
    reg->hlen = (sizeof(struct register_h) + len) / 4;
    meslen = sizeof(struct uftp_h) + (reg->hlen * 4);

    if (nb_sendto(listener, buf, meslen, 0,
               (struct sockaddr *)&(group->replyaddr),
               family_len(group->replyaddr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->file_id, "Error sending REGISTER");
    } else {
        log2(group->group_id, group->file_id, "REGISTER sent");
    }
    log3(group->group_id, 0, "send time: %d.%06d",
            send_time.tv_sec, send_time.tv_usec);

    set_timeout(group, 0);
    if (group->client_auth) {
        send_client_key(group);
    }
    free(buf);
}

/**
 * Sends a KEYINFO_ACK in response to a KEYINFO
 */
void send_keyinfo_ack(struct group_list_t *group)
{
    unsigned char *buf, *encrypted;
    struct uftp_h *header;
    struct keyinfoack_h *keyinfo_ack;
    unsigned char *verifydata, *verify_hash, *verify_val;
    unsigned int payloadlen, hashlen;
    int verifylen, enclen, len;

    buf = calloc(MAXMTU, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    keyinfo_ack = (struct keyinfoack_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, KEYINFO_ACK, group);
    keyinfo_ack->func = KEYINFO_ACK;
    keyinfo_ack->hlen = sizeof(struct keyinfoack_h) / 4;

    verifydata = build_verify_data(group, &verifylen);
    if (!verifydata) {
        log0(group->group_id, group->file_id,
                "Error getting verify data");
        send_abort(group, "Error getting verify data");
        free(buf);
        return;
    }

    verify_hash = calloc(group->hmaclen, 1);
    verify_val = calloc(VERIFY_LEN + group->hmaclen, 1);
    if ((verify_hash == NULL) || (verify_val == NULL)){
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    hash(group->hashtype, verifydata, verifylen, verify_hash, &hashlen);
    PRF(group->hashtype, VERIFY_LEN, group->groupmaster,
            sizeof(group->groupmaster), "client finished",
            verify_hash, hashlen, verify_val, &len);
    memcpy(keyinfo_ack->verify_data, verify_val, VERIFY_LEN);
    free(verifydata);
    free(verify_hash);
    free(verify_val);

    payloadlen = sizeof(struct keyinfoack_h);
    encrypted = NULL;
    if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen, group->keytype,
            group->groupkey, group->groupsalt, &group->ivctr, group->ivlen,
            group->hashtype, group->grouphmackey, group->hmaclen,group->sigtype,
            group->keyextype, group->client_privkey,group->client_privkeylen)) {
        log0(0, 0, "Error encrypting KEYINFO_ACK");
        free(buf);
        return;
    }
    payloadlen = enclen + sizeof(struct uftp_h);

    if (nb_sendto(listener, encrypted, payloadlen, 0,
               (struct sockaddr *)&(group->replyaddr),
               family_len(group->replyaddr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->file_id, "Error sending KEYINFO_ACK");
    } else {
        log2(group->group_id, group->file_id, "KEYINFO_ACK sent");
    }
    free(encrypted);
    free(buf);
}

/**
 * Sends a FILEINFO_ACK in response to a FILEINFO
 */
void send_fileinfo_ack(struct group_list_t *group, int restart)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct fileinfoack_h *fileinfo_ack;
    struct timeval now, send_time;
    unsigned int payloadlen;
    int enclen;

    buf = calloc(MAXMTU, 1);
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    header = (struct uftp_h *)buf;
    fileinfo_ack = (struct fileinfoack_h *)(buf + sizeof(struct uftp_h));

    payloadlen = sizeof(struct fileinfoack_h);
    set_uftp_header(header, FILEINFO_ACK, group);
    fileinfo_ack->func = FILEINFO_ACK;
    fileinfo_ack->hlen = sizeof(struct fileinfoack_h) / 4;
    fileinfo_ack->file_id = htons(group->file_id);
    if (restart) {
        fileinfo_ack->flags |= FLAG_PARTIAL;
    }
    gettimeofday(&now, NULL);
    if (cmptimestamp(now, group->last_server_rx_ts) <= 0) {
        send_time = group->last_server_ts;
    } else {
        send_time = add_timeval(group->last_server_ts,
                diff_timeval(now, group->last_server_rx_ts));
    }
    fileinfo_ack->tstamp_sec = htonl((uint32_t)send_time.tv_sec);
    fileinfo_ack->tstamp_usec = htonl((uint32_t)send_time.tv_usec);
    if (group->keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
                group->keytype, group->groupkey, group->groupsalt,&group->ivctr,
                group->ivlen, group->hashtype, group->grouphmackey,
                group->hmaclen, group->sigtype, group->keyextype,
                group->client_privkey, group->client_privkeylen)) {
            log0(0, 0, "Error encrypting FILEINFO_ACK");
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
               (struct sockaddr *)&(group->replyaddr),
               family_len(group->replyaddr)) == SOCKET_ERROR) {
        sockerror(group->group_id,group->file_id, "Error sending FILEINFO_ACK");
    } else {
        log2(group->group_id, group->file_id, "FILEINFO_ACK sent");
    }
    log3(group->group_id, group->file_id, "send time: %d.%06d",
            send_time.tv_sec, send_time.tv_usec);
    free(encrypted);
    free(buf);
}

/**
 * Verifies a server's public key fingerprint
 */
int verify_server_fingerprint(const unsigned char *keyblob, int bloblen,
                              struct group_list_t *group)
{
    unsigned char fingerprint[HMAC_LEN];
    unsigned int fplen;
    int found, keyidx;

    if (server_count == 0) {
        return 1;
    }

    for (keyidx = 0, found = 0; (keyidx < server_count) && !found; keyidx++) {
        if (server_keys[keyidx].uid == group->src_id) {
            keyidx--;
            found = 1;
        }
    }
    if (!found) {
        return 0;
    }
    if (!server_keys[keyidx].has_fingerprint) {
        return 1;
    }

    hash(HASH_SHA1, keyblob, bloblen, fingerprint, &fplen);
    if (memcmp(server_keys[keyidx].fingerprint, fingerprint, fplen)) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * Calculate the master key and do key expansion to determine the symmetric
 * cypher key and IV salt, and hash key for the server
 */
int calculate_server_keys(struct group_list_t *group,
                          const struct enc_info_he *encinfo)
{
    unsigned char *seed, *prf_buf;
    int explen, len, seedlen;
    time_t t;
    uint32_t t2;

    memcpy(group->rand1, encinfo->rand1, sizeof(encinfo->rand1));
    if (!get_random_bytes(group->rand2, sizeof(group->rand2))) {
        log0(group->group_id, 0, "Failed to get random bytes for rand2");
        send_abort(group, "Failed to get random bytes for rand2");
        return 0;
    }
    // Sets the first 4 bytes of rand2 to the current time
    t = time(NULL);
    t2 = (uint32_t)(t & 0xFFFFFFFF);
    *(uint32_t *)(group->rand2) = t2;
    if (group->keyextype == KEYEX_RSA) {
        if (!get_random_bytes(group->premaster, MASTER_LEN)) {
            log0(group->group_id,0, "Failed to get random bytes for premaster");
            send_abort(group, "Failed to get random bytes for premaster");
            return 0;
        }
        group->premaster_len = MASTER_LEN;
    } else {
        EC_key_t pubecdh;

        if (has_proxy) {
            pubecdh = proxy_dhkey.ec;
        } else {
            pubecdh = group->server_dhkey.ec;
        }
        if (!get_ECDH_key(pubecdh, group->client_dhkey.ec,
                          group->premaster, &group->premaster_len)) {
            log0(group->group_id,0, "Failed to calculate ECDH key");
            send_abort(group, "Failed to calculate ECDH key");
            return 0;
        }
    }

    get_key_info(group->keytype, &group->keylen, &group->ivlen);
    group->hmaclen = get_hash_len(group->hashtype);

    explen = group->keylen + SALT_LEN + group->hmaclen;
    seedlen = RAND_LEN * 2;
    seed = calloc(seedlen, 1);
    prf_buf = calloc(MASTER_LEN + explen + group->hmaclen, 1);
    if ((seed == NULL) || (prf_buf == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    memcpy(seed, group->rand1, sizeof(group->rand1));
    memcpy(seed + sizeof(group->rand1), group->rand2, sizeof(group->rand2));
    PRF(group->hashtype, MASTER_LEN, group->premaster, group->premaster_len,
            "master secret", seed, seedlen, prf_buf, &len);
    memcpy(group->master,prf_buf, sizeof(group->master));

    PRF(group->hashtype, explen, group->master, sizeof(group->master),
            "key expansion", seed, seedlen, prf_buf, &len);
    memcpy(group->hmackey, prf_buf, group->hmaclen);
    memcpy(group->key, prf_buf + group->hmaclen, group->keylen);
    memcpy(group->salt, prf_buf + group->hmaclen + group->keylen, SALT_LEN);

    free(seed);
    free(prf_buf);
    return 1;
}

/**
 * Read encryption related fields from an ANNOUNCE
 */
int read_announce_encryption(struct group_list_t *group,
                             const struct enc_info_he *encinfo,
                             const unsigned char *packet, int packetlen)
{
    int keyextype, sigtype, keytype, i;
    unsigned char *keys;

    keys = (unsigned char *)encinfo + sizeof(struct enc_info_he);
    // Sanity check the selected encryption parameters
    if (!cipher_supported(encinfo->keytype)) {
        log0(group->group_id, 0, "Keytype invalid or not supported here");
        send_abort(group, "Keytype invalid or not supported here");
        return 0;
    }
    if (!hash_supported(encinfo->hashtype)) {
        log0(group->group_id, 0, "Hashtype invalid or not supported here");
        send_abort(group, "Hashtype invalid or not supported here");
        return 0;
    }
    keyextype = (encinfo->keyextype_sigtype & 0xF0) >> 4;
    sigtype = encinfo->keyextype_sigtype & 0x0F;
    if (((sigtype != SIG_HMAC) && (sigtype != SIG_KEYEX) &&
                (sigtype != SIG_AUTHENC)) ||
            ((sigtype == SIG_AUTHENC) && (!is_auth_enc(encinfo->keytype)))) {
        log0(group->group_id, 0, "Invalid sigtype specified");
        send_abort(group, "Invalid sigtype specified");
        return 0;
    } 
    if ((keyextype != KEYEX_RSA) && (keyextype != KEYEX_ECDH_RSA) &&
            (keyextype != KEYEX_ECDH_ECDSA)) {
        log0(group->group_id, 0, "Invalid keyextype specified");
        send_abort(group, "Invalid keyextype specified");
        return 0;
    }
    group->keyextype = keyextype;
    group->keytype = encinfo->keytype;
    group->hashtype = encinfo->hashtype;
    group->sigtype = sigtype;
    group->client_auth = ((encinfo->flags & FLAG_CLIENT_AUTH) != 0);

    if (!verify_server_fingerprint(keys, ntohs(encinfo->keylen), group)) {
        log0(group->group_id, 0, "Failed to verify server key fingerprint");
        send_abort(group, "Failed to verify server key fingerprint");
        return 0;
    }

    if ((group->keyextype == KEYEX_RSA) ||
            (group->keyextype == KEYEX_ECDH_RSA)) {
        keytype = KEYBLOB_RSA;
    } else {
        keytype = KEYBLOB_EC;
    }
    // Load server key and select a matching client key
    if (keytype == KEYBLOB_RSA) {
        if (!import_RSA_key(&group->server_pubkey.rsa, keys,
                            ntohs(encinfo->keylen))) {
            log0(group->group_id, 0, "Failed to load server public key");
            send_abort(group, "Failed to load server public key");
            return 0;
        }
        group->server_pubkeylen = RSA_keylen(group->server_pubkey.rsa);
        for (i = 0; i < key_count; i++) {
            if ((privkey_type[i] == KEYBLOB_RSA) &&
                    (group->server_pubkeylen == RSA_keylen(privkey[i].rsa))) {
                group->client_privkey = privkey[i];
                group->client_privkeylen = RSA_keylen(privkey[i].rsa);
                break;
            }
        }
    } else {
        if (!import_EC_key(&group->server_pubkey.ec, keys,
                           ntohs(encinfo->keylen), 0)) {
            log0(group->group_id, 0, "Failed to load server public key");
            send_abort(group, "Failed to load server public key");
            return 0;
        }
        group->server_pubkeylen = ECDSA_siglen(group->server_pubkey.ec);
        for (i = 0; i < key_count; i++) {
            if ((privkey_type[i] == KEYBLOB_EC) &&
                    (get_EC_curve(group->server_pubkey.ec) ==
                        get_EC_curve(privkey[i].ec))) {
                group->client_privkey = privkey[i];
                group->client_privkeylen = ECDSA_siglen(privkey[i].ec);
                break;
            }
        }
    }
    if (!group->client_privkey.key) {
        log0(group->group_id, 0, "No client key compatible with server key");
        send_abort(group, "No client key compatible with server key");
        return 0;
    }
    if (has_proxy) {
        if (!proxy_pubkey.key) {
            log0(group->group_id, 0,
                    "Response proxy set but haven't gotten key yet");
            send_abort(group,"Response proxy set but haven't gotten key yet");
            return 0;
        }
        if (!(((keytype == KEYBLOB_RSA) && (proxy_pubkeytype == KEYBLOB_RSA)) &&
                    (RSA_keylen(group->server_pubkey.rsa) ==
                        RSA_keylen(proxy_pubkey.rsa))) &&
                !(((keytype == KEYBLOB_EC) && (proxy_pubkeytype==KEYBLOB_EC)) &&
                    (get_EC_curve(group->server_pubkey.ec) ==
                        get_EC_curve(proxy_pubkey.ec)))) {
            log0(group->group_id, 0,
                    "Response proxy key not compatible with server key");
            send_abort(group,
                    "Response proxy key not compatible with server key");
            return 0;
        }
    }
    if ((group->keyextype == KEYEX_ECDH_ECDSA) ||
            (group->keyextype == KEYEX_ECDH_RSA)) {
        unsigned char *sigcopy;
        int siglen;
        unsigned char *dhblob = keys + ntohs(encinfo->keylen);
        unsigned char *sig = dhblob + ntohs(encinfo->dhlen);

        if (!import_EC_key(&group->server_dhkey.ec, dhblob,
                           ntohs(encinfo->dhlen), 1)) {
            log0(group->group_id, 0, "Failed to load server public ECDH key");
            send_abort(group, "Failed to load server public ECDH key");
            return 0;
        }

        group->client_dhkey.ec =
                gen_EC_key(get_EC_curve(group->server_dhkey.ec), 1, NULL);
        if (!group->client_dhkey.key) {
            log0(group->group_id, 0, "Failed to generate client ECDH key");
            send_abort(group, "Failed to generate client ECDH key");
            return 0;
        }
        if (has_proxy) {
            // We already checked if the proxy key exists, so no need to repeat
            if (get_EC_curve(group->server_dhkey.ec) !=
                    get_EC_curve(proxy_dhkey.ec)) {
                log0(group->group_id, 0, "Response proxy ECDH key "
                        "not compatible with server ECDH key");
                send_abort(group, "Response proxy ECDH key "
                        "not compatible with server ECDH key");
                return 0;
            }
        }

        siglen = ntohs(encinfo->siglen);
        sigcopy = calloc(siglen, 1);
        if (sigcopy == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        memcpy(sigcopy, sig, siglen);
        memset(sig, 0, siglen);
        if (keytype == KEYBLOB_RSA) {
            if (!verify_RSA_sig(group->server_pubkey.rsa, group->hashtype,
                                packet, packetlen, sigcopy, siglen)) {
                log0(group->group_id, 0, "Signature verification failed");
                send_abort(group, "Signature verification failed");
                free(sigcopy);
                return 0;
            }
        } else {
            if (!verify_ECDSA_sig(group->server_pubkey.ec, group->hashtype,
                                  packet, packetlen, sigcopy, siglen)) {
                log0(group->group_id, 0, "Signature verification failed");
                send_abort(group, "Signature verification failed");
                free(sigcopy);
                return 0;
            }
        }
        free(sigcopy);
    }

    // Calculate keys
    if (!calculate_server_keys(group, encinfo)) {
        return 0;
    }

    return 1;
}

/**
 * Read in the contents of an ANNOUNCE.
 */
int read_announce(struct group_list_t *group, const unsigned char *packet,
                  union sockaddr_u *src, struct timeval rxtime, int packetlen)
{
    struct uftp_h *header;
    struct announce_h *announce;
    struct enc_info_he *encinfo;
    uint8_t *publicmcast, *privatemcast;
    const uint8_t *he;
    unsigned int iplen, extlen;

    header = (struct uftp_h *)packet;
    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    encinfo = NULL;

    group->phase = PHASE_REGISTERED;
    group->version = header->version;
    group->group_id = ntohl(header->group_id);
    group->group_inst = header->group_inst;
    group->src_id = header->src_id;
    if (has_proxy) {
        group->replyaddr = proxy_info.addr;
    } else {
        group->replyaddr = *src;
    }
    group->grtt = unquantize_grtt(header->grtt);
    group->rtt = 0;
    group->robust = announce->robust;
    group->cc_type = announce->cc_type;
    group->gsize = unquantize_gsize(header->gsize);
    group->blocksize = ntohs(announce->blocksize);
    group->last_server_ts.tv_sec = ntohl(announce->tstamp_sec);
    group->last_server_ts.tv_usec = ntohl(announce->tstamp_usec);
    group->last_server_rx_ts = rxtime;
    group->restart = ((group->group_inst != 0) && (strcmp(tempdir, "")));
    group->sync_preview = ((announce->flags & FLAG_SYNC_PREVIEW) != 0);
    group->sync_mode = group->sync_preview ||
            ((announce->flags & FLAG_SYNC_MODE) != 0);
    iplen = ((announce->flags & FLAG_IPV6) != 0) ?
                sizeof(struct in6_addr) : sizeof(struct in_addr);
    publicmcast = ((uint8_t *)announce) + sizeof(struct announce_h);
    privatemcast = publicmcast + iplen;
    if ((announce->flags & FLAG_IPV6) != 0) {
        group->multi.sin6.sin6_family = AF_INET6;
        memcpy(&group->multi.sin6.sin6_addr.s6_addr, privatemcast, iplen);
    } else {
        group->multi.sin.sin_family = AF_INET;
        memcpy(&group->multi.sin.sin_addr.s_addr, privatemcast, iplen);
    }
    group->fileinfo.fd = -1;

    if ((announce->hlen * 4U) < sizeof(struct announce_h) + (2U * iplen)) {
        log0(group->group_id, 0, "Rejecting ANNOUNCE from %08X: "
                          "invalid header size", ntohl(group->src_id));
        send_abort(group, "Invalid header size");
        return 0;
    }
    if ((announce->hlen * 4U) > sizeof(struct announce_h) + (2U * iplen)) {
        he = (unsigned char *)announce + sizeof(struct announce_h) +
                (2U * iplen);
        if (*he == EXT_ENC_INFO) {
            encinfo = (struct enc_info_he *)he;
            extlen = encinfo->extlen * 4U;
            if ((extlen > ((announce->hlen * 4U) -
                            sizeof(struct announce_h))) ||
                    (extlen < sizeof(struct enc_info_he)) ||
                    (extlen != (sizeof(struct enc_info_he) +
                                ntohs(encinfo->keylen) + ntohs(encinfo->dhlen) +
                                ntohs(encinfo->siglen)))) {
                log0(group->group_id, 0, "Rejecting ANNOUNCE from %08X: "
                        "invalid extension size", ntohl(group->src_id));
                send_abort(group, "Invalid extension size");
                return 0;
            }
        }
    }

    if (encinfo != NULL) {
        if (!read_announce_encryption(group, encinfo, packet, packetlen)) {
            return 0;
        }
    } else if (encrypted_only) {
        log0(group->group_id, 0, "No unencrypted transfers allowed");
        send_abort(group, "No unencrypted transfers allowed");
        return 0;
    } else {
        group->keyextype = KEYEX_NONE;
        group->keytype = KEY_NONE;
        group->hashtype = HASH_NONE;
        group->sigtype = SIG_NONE;
        group->client_auth = 0;
    }
    gettimeofday(&group->expire_time, NULL);
    if (group->robust * group->grtt < 1.0) {
        add_timeval_d(&group->expire_time, 1.0);
    } else {
        add_timeval_d(&group->expire_time, group->robust * group->grtt);
    }
    group->fileinfo.nak_time.tv_sec = 0;
    group->fileinfo.nak_time.tv_usec = 0;

    // Size of data packet, used in transmission speed calculations
    group->datapacketsize = group->blocksize + sizeof(struct fileseg_h);
    if (group->cc_type == CC_TFMCC) {
        group->datapacketsize += sizeof(struct tfmcc_data_info_he);
    }
    if (group->keytype != KEY_NONE) {
        group->datapacketsize += ((group->sigtype == SIG_KEYEX) ?
                group->server_pubkeylen : (group->sigtype == SIG_HMAC) ?
                group->hmaclen : 0) + KEYBLSIZE + sizeof(struct encrypted_h);
    }
    // 8 = UDP size, 20 = IPv4 size, 40 = IPv6 size
    if ((announce->flags & FLAG_IPV6) != 0) {
        group->datapacketsize += sizeof(struct uftp_h) + 8 + 40;
    } else {
        group->datapacketsize += sizeof(struct uftp_h) + 8 + 20;
    }

    if (group->cc_type != CC_NONE) {
        group->loss_history = calloc(0x10000, sizeof(struct loss_history_t));
        if (group->loss_history == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        group->slowstart = 1;
        group->seq_wrap = 0;
        group->start_txseq = ntohs(header->seq);
        group->max_txseq = group->start_txseq;
        group->loss_history[group->start_txseq].found = 1;
        group->loss_history[group->start_txseq].t = rxtime;
        group->loss_history[group->start_txseq].size = packetlen;
    }

    return 1;
}

/**
 * Processes a new incoming ANNOUNCE
 */
void handle_announce(union sockaddr_u *src, const unsigned char *packet,
                     unsigned packetlen, struct timeval rxtime)
{
    struct uftp_h *header;
    struct announce_h *announce;
    uint32_t *addrlist;
    int addrlen, rval;
    struct group_list_t *group;
    time_t t;
    struct tm *start_time;
    char privname[INET6_ADDRSTRLEN];

    header = (struct uftp_h *)packet;
    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((unsigned char *)announce + (announce->hlen * 4));
    addrlen = (packetlen - sizeof(struct uftp_h) - (announce->hlen * 4)) / 4;

    if ((packetlen < sizeof(struct uftp_h) + (announce->hlen * 4U)) ||
            ((announce->hlen * 4U) < sizeof(struct announce_h))) {
        log0(ntohl(header->group_id), 0, "Rejecting ANNOUNCE from %08X: "
                "invalid message size", ntohl(header->src_id));
        return;
    }

    if ((addrlen != 0) && (!uid_in_list(addrlist, addrlen))) {
        log1(ntohl(header->group_id), 0, "Name not in host list");
        return;
    }

    if ((group = find_open_slot()) == NULL ) {
        log0(ntohl(header->group_id), 0,
            "Error: maximum number of incoming files exceeded: %d\n", MAXLIST);
        return;
    }

    t = time(NULL);
    start_time = localtime(&t);
    snprintf(group->start_date, sizeof(group->start_date), "%04d%02d%02d",
            start_time->tm_year + 1900,
            start_time->tm_mon + 1, start_time->tm_mday);
    snprintf(group->start_time, sizeof(group->start_time), "%02d%02d%02d",
            start_time->tm_hour, start_time->tm_min, start_time->tm_sec);

    if (!read_announce(group, packet, src, rxtime, packetlen)) {
        return;
    }

    if ((rval = getnameinfo((struct sockaddr *)&group->multi,
            family_len(group->multi), privname, sizeof(privname),
            NULL, 0, NI_NUMERICHOST)) != 0) {
        log1(0, 0, "getnameinfo failed: %s", gai_strerror(rval));
    }

    log0(group->group_id,0, "Received request from %08X", ntohl(group->src_id));
    log1(group->group_id, 0, "Using private multicast address %s", privname);
    log3(group->group_id, 0, "grtt = %.6f", group->grtt);
    log3(group->group_id, 0, "send time: %d.%06d",
            group->last_server_ts.tv_sec, group->last_server_ts.tv_usec);
    log3(group->group_id, 0, "receive time: %d.%06d",
            group->last_server_rx_ts.tv_sec, group->last_server_rx_ts.tv_usec);

    if (group->restart) {
        if (group->sync_mode) {
            log0(group->group_id, 0, "Sync mode and restart mode incompatable");
            send_abort(group, "Sync mode and restart mode incompatable");
            return;
        }
    }

    if (!addr_blank(&group->multi)) {
        if (server_count > 0) {
            if (!is_multicast(&group->multi, 1)) {
                log0(group->group_id, 0,
                        "Invalid source specific multicast address: %s",
                        privname);
                send_abort(group, "Invalid source specific multicast address");
                return;
            }
            if (!multicast_join(listener, group->group_id, &group->multi,
                    m_interface, interface_count, server_keys, server_count)) {
                send_abort(group, "Error joining multicast group");
                return;
            }
            if (has_proxy) {
                if (!multicast_join(listener, group->group_id, &group->multi,
                        m_interface, interface_count, &proxy_info, 1)) {
                    send_abort(group, "Error joining multicast group");
                    return;
                }
            }
        } else {
            if (!is_multicast(&group->multi, 0)) {
                log0(group->group_id, 0, "Invalid multicast address: %s",
                        privname);
                send_abort(group, "Invalid multicast address");
                return;
            }
            if (!multicast_join(listener, group->group_id,
                    &group->multi, m_interface, interface_count, NULL, 0)) {
                send_abort(group, "Error joining multicast group");
                return;
            }
        }
        group->multi_join = 1;
    }

    send_register(group);
}

/**
 * Processes an incoming REG_CONF message.
 * Expected in response to a REGISTER when encryption is disabled.
 */
void handle_regconf(struct group_list_t *group, const unsigned char *message,
                    unsigned meslen)
{
    struct regconf_h *regconf;
    uint32_t *addrlist;
    int addrcnt;

    regconf = (struct regconf_h *)message;
    addrlist = (uint32_t *)(message + (regconf->hlen * 4));

    if ((meslen < (regconf->hlen * 4U)) ||
            ((regconf->hlen * 4U) < sizeof(struct regconf_h))) {
        log1(group->group_id, 0,
                "Rejecting REG_CONF from server: invalid message size");
        return;
    }

    addrcnt = (meslen - (regconf->hlen * 4)) / 4;
    if (uid_in_list(addrlist, addrcnt)) {
        log2(group->group_id, 0, "Registration confirmed");
        group->phase = PHASE_MIDGROUP;
        set_timeout(group, 0);
    }
    if (group->restart) {
        read_restart_file(group);
    }
}

/**
 * Process an incoming KEYINFO message.
 * Expected in response to a REGISTER when encryption is enabled.
 */
void handle_keyinfo(struct group_list_t *group, const unsigned char *message,
                    unsigned meslen, uint32_t src_id)
{
    struct keyinfo_h *keyinfo;
    struct destkey *keylist;
    int i, keyidx, len, destkeycnt, unauth_keytype, unauth_keylen, unauth_ivlen;
    unsigned explen, declen;
    uint8_t decgroupmaster[MASTER_LEN], *prf_buf, *iv;
    uint64_t ivctr;

    keyinfo = (struct keyinfo_h *)message;
    keylist = (struct destkey *)(message + (keyinfo->hlen * 4));

    if ((meslen < (keyinfo->hlen * 4U)) ||
            ((keyinfo->hlen * 4U) < sizeof(struct keyinfo_h))) {
        log1(group->group_id, 0,
                "Rejecting KEYINFO from server: invalid message size");
        return;
    }

    destkeycnt = (meslen - (keyinfo->hlen * 4)) / sizeof(struct destkey);
    // This duplicates uid_in_list, but here it's addressed in a struct array
    for (i = 0, keyidx = -1; (i < destkeycnt) && (keyidx == -1); i++) {
        if (uid == keylist[i].dest_id) {
            keyidx = i;
        }
    }

    // Don't use a cipher in an authentication mode to decrypt the group master
    unauth_keytype = unauth_key(group->keytype);
    get_key_info(unauth_keytype, &unauth_keylen, &unauth_ivlen);
    if (keyidx != -1) {
        log2(group->group_id, 0, "Received KEYINFO");
        if (group->phase == PHASE_MIDGROUP) {
            // We already got the KEYINFO, so no need to reprocess.
            // Just resend the KEYINFO_ACK and reset the timeout
            send_keyinfo_ack(group);
            set_timeout(group, 0);
            return;
        }

        iv = calloc(unauth_ivlen, 1);
        if (iv == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        ivctr = ntohl(keyinfo->iv_ctr_lo);
        ivctr |= (uint64_t)ntohl(keyinfo->iv_ctr_hi) << 32;
        build_iv(iv, group->salt, unauth_ivlen, uftp_htonll(ivctr), src_id);
        if (!decrypt_block(unauth_keytype, iv, group->key, NULL, 0,
                    keylist[keyidx].groupmaster, MASTER_LEN,
                    decgroupmaster, &declen) ||
                (declen != MASTER_LEN - 1)) {
            log0(group->group_id, 0, "Decrypt failed for group master");
            send_abort(group, "Decrypt failed for group master");
            free(iv);
            return;
        }
        free(iv);
        group->groupmaster[0] = group->version;
        memcpy(&group->groupmaster[1], decgroupmaster, declen);

        explen = group->keylen + SALT_LEN + group->hmaclen;
        prf_buf = calloc(explen + group->hmaclen, 1);
        if (prf_buf == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        PRF(group->hashtype, explen, group->groupmaster,
                sizeof(group->groupmaster), "key expansion",
                group->rand1, sizeof(group->rand1), prf_buf, &len);
        memcpy(group->grouphmackey, prf_buf, group->hmaclen);
        memcpy(group->groupkey, prf_buf + group->hmaclen, group->keylen);
        memcpy(group->groupsalt, prf_buf + group->hmaclen + group->keylen,
                SALT_LEN);

        free(prf_buf);
        group->phase = PHASE_MIDGROUP;
        send_keyinfo_ack(group);
        set_timeout(group, 0);

        if (group->restart) {
            read_restart_file(group);
        }
    }
}

/**
 * Send a COMPLETE with the given status in reponse to a FILEINFO,
 * set the phase to MIDGROUP, and reset the timeout
 */
void early_complete(struct group_list_t *group, int status)
{
    group->phase = PHASE_MIDGROUP;
    group->fileinfo.comp_status = status;
    send_complete(group);
    set_timeout(group, 0);
}

/**
 * Read in the contents of a FILEINFO message
 * Returns 1 on success, 0 on error or ignore
 */
int read_fileinfo(struct group_list_t *group, const unsigned char *message,
                  int meslen, struct timeval rxtime)
{
    struct fileinfo_h *fileinfo;
    uint32_t *addrlist;
    int listlen, maxsecsize;
    char *name, *link, *p;

    fileinfo = (struct fileinfo_h *)message;
    addrlist = (uint32_t *)(message + (fileinfo->hlen * 4));
    name = (char *)message + sizeof(struct fileinfo_h);
    link = name + (fileinfo->namelen * 4);
    listlen = (meslen - (fileinfo->hlen * 4)) / 4;

    if ((meslen < (fileinfo->hlen * 4)) ||
            ((fileinfo->hlen * 4) < sizeof(struct fileinfo_h)) ||
            ((fileinfo->namelen * 4) > MAXPATHNAME) ||
            ((fileinfo->linklen * 4) > MAXPATHNAME) ||
            ((fileinfo->hlen * 4) != sizeof(struct fileinfo_h) +
                (fileinfo->namelen * 4) + (fileinfo->linklen * 4))) {
        log1(group->group_id, group->file_id,
                "Rejecting FILEINFO from server: invalid message size");
        send_abort(group, "Rejecting FILEINFO: invalid message size");
        return 0;
    }
    if (!uid_in_list(addrlist, listlen)) {
        set_timeout(group, 0);
        return 0;
    }

    if (group->phase == PHASE_RECEIVING) {
        // We already got the FILEINFO, so no need to reprocess.
        // Just resend the INFO_ACK and reset the timeout
        send_fileinfo_ack(group, group->fileinfo.restart);
        set_timeout(group, 0);
        return 0;
    }
    if ((group->phase == PHASE_MIDGROUP) &&
            (group->file_id == ntohs(fileinfo->file_id))) {
        // We already got the FILEINFO, and it's for a completed file.
        // So resend the COMPLETE and reset the timeout
        send_complete(group);
        set_timeout(group, 0);
        return 0;
    }

    // Load fileinfo params into list
    memset(&group->fileinfo, 0, sizeof(struct file_t));
    group->fileinfo.ftype = fileinfo->ftype;
    group->file_id = ntohs(fileinfo->file_id);
    strncpy(group->fileinfo.name, name, fileinfo->namelen * 4);
    strncpy(group->fileinfo.linkname, link, fileinfo->linklen * 4);
    group->fileinfo.size = (f_offset_t)ntohs(fileinfo->hifsize) << 32;
    group->fileinfo.size |= ntohl(fileinfo->lofsize);

    maxsecsize = (group->blocksize * 8 > MAXSECTION ?
            MAXSECTION : group->blocksize * 8);
    group->fileinfo.blocks =
            (int32_t)((group->fileinfo.size / group->blocksize) +
            (group->fileinfo.size % group->blocksize ? 1 : 0));
    group->fileinfo.sections = (group->fileinfo.blocks / maxsecsize) +
            (group->fileinfo.blocks % maxsecsize ? 1 : 0);
    group->fileinfo.secsize_small =
            group->fileinfo.blocks / group->fileinfo.sections;
    group->fileinfo.secsize_big = group->fileinfo.secsize_small +
            (group->fileinfo.blocks % group->fileinfo.sections ? 1 : 0);
    group->fileinfo.big_sections = group->fileinfo.blocks -
            (group->fileinfo.secsize_small * group->fileinfo.sections);

    group->fileinfo.tstamp = ntohl(fileinfo->ftstamp);
    group->last_server_ts.tv_sec = ntohl(fileinfo->tstamp_sec);
    group->last_server_ts.tv_usec = ntohl(fileinfo->tstamp_usec);
    group->last_server_rx_ts = rxtime;
    group->fileinfo.fd = -1;

    // Run some checks on the filename
    if (strlen(group->fileinfo.name) == 0) {
        log1(group->group_id, ntohs(fileinfo->file_id),
                "Rejecting FILEINFO from server: blank file name");
        early_complete(group, COMP_STAT_REJECTED);
        return 0;
    }
    p = strstr(group->fileinfo.name, "..");
    if ((p != NULL) && ((p[2] == '\x0') || (p[2] == '/') || (p[2] == '\\')) &&
            ((p == name) || (p[-1] == '/') || (p[-1] == '\\'))) {
        log1(group->group_id, ntohs(fileinfo->file_id),
                "Rejecting FILEINFO from server: filename contains ..");
        early_complete(group, COMP_STAT_REJECTED);
        return 0;
    }
    if (fileinfo->ftype == FTYPE_LINK) {
        if (strlen(group->fileinfo.linkname) == 0) {
            log1(group->group_id, group->file_id,
                    "Rejecting FILEINFO from server: blank link name");
            early_complete(group, COMP_STAT_REJECTED);
            return 0;
        }
    }

    return 1;
}

/**
 * Validate and establish the destination name of an incoming file.
 * Returns 0 if the file was rejected for some reason, 1 otherwise.
 */
int setup_dest_file(struct group_list_t *group)
{
    int found_dest_dir, len, i;
    int (*cmp)(const char *, const char *);
    int (*ncmp)(const char *, const char *, size_t);

#if PATH_SEP != '/'
    // First translate any '/' in the sent file name to PATH_SEP
    {
        char *p;
        while ((p = strchr(group->fileinfo.name, '/')) != NULL) {
            *p = PATH_SEP;
        }
    }
#endif

#ifdef WINDOWS
    cmp = stricmp;
    ncmp = strnicmp;
#else
    cmp = strcmp;
    ncmp = strncmp;
#endif

    if (isfullpath(group->fileinfo.name)) {
        if (strcmp(tempdir, "")) {
            log0(group->group_id, group->file_id,
                    "Rejecting file with absolute pathname: "
                    "temp directory is in use");
            early_complete(group, COMP_STAT_REJECTED);
            return 0;
        }
        for (found_dest_dir = 0, i = 0; i < destdircnt; i++) {
            if (!ncmp(group->fileinfo.name, destdir[i], strlen(destdir[i]))) {
                if (!cmp(group->fileinfo.name, destdir[i])) {
                    log0(group->group_id, group->file_id,
                            "Rejecting file with absolute pathname: "
                            "can't have the same name as a dest directory");
                    early_complete(group, COMP_STAT_REJECTED);
                    return 0;
                } else {
                    found_dest_dir = 1;
                    break;
                }
            }
        }
        if (!found_dest_dir) {
            log0(group->group_id, group->file_id,
                    "Rejecting file with absolute pathname: "
                    "doesn't match any dest directory");
            early_complete(group, COMP_STAT_REJECTED);
            return 0;
        }
        group->fileinfo.destdiridx = i;
        snprintf(group->fileinfo.filepath,
            sizeof(group->fileinfo.filepath), "%s", group->fileinfo.name);
    } else {
        if (!strcmp(tempdir, "")) {
            len = snprintf(group->fileinfo.filepath,
                    sizeof(group->fileinfo.filepath), "%s%c%s",
                    destdir[0], PATH_SEP, group->fileinfo.name);
        } else {
            len = snprintf(group->fileinfo.filepath,
                    sizeof(group->fileinfo.filepath),
                    "%s%c_group_%08X%c%s", tempdir, PATH_SEP, group->group_id,
                    PATH_SEP, group->fileinfo.name);
        }
        if (len >= sizeof(group->fileinfo.filepath)) {
            log0(group->group_id, group->file_id,
                    "Rejecting file: max pathname length exceeded");
            early_complete(group, COMP_STAT_REJECTED);
            return 0;
        }

    }
    len = snprintf(group->fileinfo.temppath, sizeof(group->fileinfo.temppath),
                   "%s.~uftp-%08X-%04X", group->fileinfo.filepath,
                   group->group_id, group->file_id);
    if (len >= sizeof(group->fileinfo.temppath)) {
        log0(group->group_id, group->file_id,
                "Rejecting file: max pathname length exceeded");
        early_complete(group, COMP_STAT_REJECTED);
        return 0;
    }
    return 1;
}

/**
 * Perform FILEINFO processing specific to a regular file in restart mode
 * Returns 1 if a COMPLETE was sent in response, 0 otherwise
 */
int handle_fileinfo_restart(struct group_list_t *group)
{
    stat_struct statbuf;

    if ((!strcmp(group->fileinfo.name, group->restartinfo->name)) &&
            (group->fileinfo.size == group->restartinfo->size) &&
            (group->fileinfo.blocks == group->restartinfo->blocks) &&
            (group->fileinfo.sections == group->restartinfo->sections)) {
        // Flag this file to restart a failed transfer
        group->fileinfo.restart = 1;
        return 0;
    } else if ((lstat_func(group->fileinfo.filepath, &statbuf) != -1) &&
               S_ISREG(statbuf.st_mode) &&
               (statbuf.st_size == group->fileinfo.size)) {
        // This file was finished on the last attempt,
        // so respond with a COMPLETE right away
        early_complete(group, COMP_STAT_NORMAL);
        return 1;
    }
    return 0;
}

/**
 * Perform FILEINFO processing specific to a regular file in sync mode
 * Returns 1 if a COMPLETE was sent in response, 0 otherwise
 */
int handle_fileinfo_sync(struct group_list_t *group)
{
    stat_struct statbuf;

    if (lstat_func(group->fileinfo.filepath, &statbuf) != -1) {
        // If source is newer, skip
        // If source is older, overwrite
        // If timstamps same, skip if sizes are also same
        int skip;
        if (group->fileinfo.tstamp < statbuf.st_mtime) {
            skip = 1;
        } else if (group->fileinfo.tstamp > statbuf.st_mtime) {
            skip = 0;
        } else if (S_ISREG(statbuf.st_mode) &&
                   (statbuf.st_size == group->fileinfo.size)) {
            skip = 1;
        } else {
            skip = 0;
        }
        if (skip) {
            if (log_level >= 1) {
                log1(group->group_id, group->file_id, "skipping file, in sync");
            } else {
                log0(group->group_id, group->file_id,
                        "Skip %s", group->fileinfo.name);
            }
            early_complete(group, COMP_STAT_SKIPPED);
            return 1;
        } else {
            if (log_level >= 1) {
                log1(group->group_id, group->file_id,
                        "overwriting out of sync file");
            } else {
                log0(group->group_id, group->file_id,
                        "Overwrite %s", group->fileinfo.name);
            }
            group->fileinfo.comp_status = COMP_STAT_OVERWRITE;
            if (group->sync_preview) {
                log1(group->group_id, group->file_id,
                        "Sync preview mode, skipping receive");
                early_complete(group, COMP_STAT_OVERWRITE);
                return 1;
            }
            if (!tempfile) {
                move_to_backup(group);
            }
        }
    } else {
        if (log_level >= 1) {
            log1(group->group_id, group->file_id, "copying new file");
        } else {
            log0(group->group_id, group->file_id,
                    "Copy %s", group->fileinfo.name);
        }
        if (group->sync_preview) {
            log1(group->group_id, group->file_id,
                    "Sync preview mode, skipping receive");
            early_complete(group, COMP_STAT_NORMAL);
            return 1;
        }
        if (!tempfile) {
            move_to_backup(group);
        }
    }
    return 0;
}

/**
 * Perform FILEINFO processing specific to a regular file
 */
void handle_fileinfo_regular(struct group_list_t *group)
{
    // First handle restart or sync mode,
    // then create/open the file.
    if (group->restartinfo) {
        if (handle_fileinfo_restart(group)) {
            return;
        }
    } else if (group->sync_mode) {
        if (handle_fileinfo_sync(group)) {
            return;
        }
    }
    if (group->fileinfo.restart) {
        group->fileinfo.fd = open(group->fileinfo.filepath, OPENWRITE);
    } else {
        const char *filename;
        if (tempfile) {
            filename = group->fileinfo.temppath;
        } else {
            filename = group->fileinfo.filepath;
        }
#ifdef WINDOWS
        SetFileAttributes(filename, FILE_ATTRIBUTE_NORMAL);
#else
        chmod(filename, 0644);
#endif
        group->fileinfo.fd = open(filename, OPENWRITE | O_CREAT | O_TRUNC,0644);
    }
    if (group->fileinfo.fd == -1) {
        syserror(group->group_id, group->file_id, "Error opening data file");
        early_complete(group, COMP_STAT_REJECTED);
        return;
    }

    // Final preparations for receiving a file.
    if (group->fileinfo.restart) {
        group->fileinfo.naklist = group->restartinfo->naklist;
        group->fileinfo.section_done = group->restartinfo->section_done;
        group->restartinfo->naklist = NULL;
        group->restartinfo->section_done = NULL;
        free(group->restartinfo);
        group->restartinfo = NULL;
    } else {
        group->fileinfo.naklist = calloc(group->fileinfo.blocks, 1);
        if (group->fileinfo.naklist == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        group->fileinfo.section_done = calloc(group->fileinfo.sections, 1);
        if (group->fileinfo.section_done == NULL) {
            syserror(0, 0, "calloc failed!");
            exit(1);
        }
        memset(group->fileinfo.naklist, 1, group->fileinfo.blocks);
    }
    group->fileinfo.last_block = -1;
    group->fileinfo.last_section = 1;
    group->fileinfo.curr_offset = 0;
    group->phase = PHASE_RECEIVING;
    send_fileinfo_ack(group, group->fileinfo.restart);
    set_timeout(group, 0);
}

/**
 * Perform FILEINFO processing specific to an empty directory
 */
void handle_fileinfo_dir(struct group_list_t *group, int found_dir)
{
    if (!found_dir && !group->sync_preview) {
        log2(group->group_id, group->file_id, "Creating directory");
        if (mkdir(group->fileinfo.filepath, 0755) == -1) {
            syserror(group->group_id, group->file_id,
                     "Failed to create directory %s", group->fileinfo.filepath);
            early_complete(group, COMP_STAT_REJECTED);
            return;
        }
    }
    early_complete(group, found_dir ? COMP_STAT_SKIPPED : COMP_STAT_NORMAL);
}

/**
 * Perform FILEINFO processing specific to a symbolic link
 */
void handle_fileinfo_link(struct group_list_t *group)
{
#ifndef WINDOWS
    if (!group->sync_preview)
        if (symlink(group->fileinfo.linkname, group->fileinfo.filepath) == -1) {
            syserror(group->group_id, group->file_id,
                     "Failed to create symlink %s", group->fileinfo.filepath);
            early_complete(group, COMP_STAT_REJECTED);
        return;
    }
#endif
    early_complete(group, COMP_STAT_NORMAL);
}

/**
 * Process an incoming FILEINFO message.
 * Expected in the middle of a group with no current file.
 */
void handle_fileinfo(struct group_list_t *group, const unsigned char *message,
                     unsigned meslen, struct timeval rxtime)
{
    stat_struct statbuf;
    int found_dir;

    if (!read_fileinfo(group, message, meslen, rxtime)) {
        return;
    }

    if (!group->sync_mode || (log_level >= 1)) {
        log0(group->group_id, group->file_id,
             "Name of file to receive: %s", group->fileinfo.name);
    }
    switch (group->fileinfo.ftype) {
    case FTYPE_REG:
        log1(group->group_id, group->file_id,
                "Bytes: %s, Blocks: %d, Sections: %d",
                printll(group->fileinfo.size),
                group->fileinfo.blocks, group->fileinfo.sections);
        log3(group->group_id, group->file_id, "small section size: %d, "
                "big section size: %d, # big sections: %d",
                group->fileinfo.secsize_small, group->fileinfo.secsize_big,
                group->fileinfo.big_sections);
        break;
    case FTYPE_DIR:
        log1(group->group_id, group->file_id, "Empty directory");
        break;
    case FTYPE_LINK:
        log1(group->group_id, group->file_id,
                "Symbolic link to %s", group->fileinfo.linkname);
        break;
    default:
        log1(group->group_id, group->file_id,
                 "Invalid file type: %d", group->fileinfo.ftype);
        send_abort(group, "Invalid file type");
        return;
    }

    if (!setup_dest_file(group)) {
        // A rejected file is still a success because we responded with a
        // COMPLETE with status=rejected instead of with an ABORT
        return;
    }

    // Make sure the path to the destination file exists and
    // remove or back up any existing file
    if (!create_path_to_file(group, group->fileinfo.filepath)) {
        log0(group->group_id, group->file_id,
                 "Error creating path to data file");
        early_complete(group, COMP_STAT_REJECTED);
        return;
    }
    found_dir = 0;
    if (tempfile && !group->sync_preview) {
        clear_path(group->fileinfo.temppath, group);
    }
    if (lstat_func(group->fileinfo.filepath, &statbuf) != -1) {
        log3(group->group_id, group->file_id, "checking existing file");
        if ((group->fileinfo.ftype != FTYPE_DIR) || !S_ISDIR(statbuf.st_mode)) {
            if ((group->fileinfo.ftype != FTYPE_REG) ||
                    !S_ISREG(statbuf.st_mode) ||
                    ((!group->restart) && (!group->sync_mode))) {
                // Don't clear/backup if we're receiving a regular file
                // and we're in either restart mode or sync mode
                log3(group->group_id, group->file_id, "calling move_to_backup");
                if (!tempfile) {
                    move_to_backup(group);
                }
            }
        } else {
            log3(group->group_id, group->file_id, "found dir");
            found_dir = 1;
        }
    } else if (errno != ENOENT) {
        syserror(group->group_id, group->file_id,
                "Error checking file %s",group->fileinfo.filepath);
    }

    switch (group->fileinfo.ftype) {
    case FTYPE_REG:
        handle_fileinfo_regular(group);
        break;
    case FTYPE_DIR:
        handle_fileinfo_dir(group, found_dir);
        break;
    case FTYPE_LINK:
        handle_fileinfo_link(group);
        break;
    default:
        log0(group->group_id, group->file_id,
                "Error handling FILEINFO: shouldn't get here!");
    }
}