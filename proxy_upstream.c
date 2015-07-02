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
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <ws2tcpip.h>

#include "win_func.h"

#else

#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "proxy.h"
#include "proxy_common.h"
#include "proxy_upstream.h"
#include "proxy_downstream.h"

/**
 * Finds next open slot in the global group list.
 * Returns a pointer to the open slot, or NULL if none found.
 */
struct pr_group_list_t *find_open_slot(void)
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
 * Calculate the master key and do key expansion to determine the symmetric
 * cypher key and IV salt, and hash key for the server
 */
int calculate_server_keys(struct pr_group_list_t *group,
                          const struct enc_info_he *encinfo)
{
    unsigned char *seed, *prf_buf;
    int explen, len, seedlen;
    time_t t;
    uint32_t t2;

    memcpy(group->rand1, encinfo->rand1, sizeof(encinfo->rand1));
    if (!get_random_bytes(group->rand2, sizeof(group->rand2))) {
        glog0(group, "Failed to get random bytes for rand2");
        send_upstream_abort(group, 0, "Failed to get random bytes for rand2");
        return 0;
    }
    // Sets the first 4 bytes of rand2 to the current time
    t = time(NULL);
    t2 = (uint32_t)(t & 0xFFFFFFFF);
    *(uint32_t *)(group->rand2) = t2;
    if (group->keyextype == KEYEX_RSA) {
        if (!get_random_bytes(group->premaster, MASTER_LEN)) {
            glog0(group, "Failed to get random bytes for premaster");
            send_upstream_abort(group, 0,
                    "Failed to get random bytes for premaster");
            return 0;
        }
        group->premaster_len = MASTER_LEN;
    } else {
        if (!get_ECDH_key(group->server_dhkey.ec, group->proxy_dhkey.ec,
                          group->premaster, &group->premaster_len)) {
            glog0(group, "Failed to calculate ECDH key");
            send_upstream_abort(group, 0, "Failed to calculate ECDH key");
            return 0;
        }
    }

    get_key_info(group->keytype, &group->keylen, &group->ivlen);
    group->hmaclen = get_hash_len(group->hashtype);

    explen = group->keylen + SALT_LEN + group->hmaclen;
    seedlen = RAND_LEN * 2;
    seed = safe_calloc(seedlen, 1);
    prf_buf = safe_calloc(MASTER_LEN + explen + group->hmaclen, 1);

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
int read_announce_encryption(struct pr_group_list_t *group,
                             struct enc_info_he *encinfo,
                             const unsigned char *packet, int packetlen)
{
    int keyextype, sigtype, keytype, i;
    unsigned char *keys;

    keys = (unsigned char *)encinfo + sizeof(struct enc_info_he);
    // Sanity check the selected encryption parameters
    if (!cipher_supported(encinfo->keytype)) {
        glog1(group, "Keytype invalid or not supported here");
        send_upstream_abort(group, 0, "Keytype invalid or not supported here");
        return 0;
    }
    if (!hash_supported(encinfo->hashtype)) {
        glog1(group, "Hashtype invalid or not supported here");
        send_upstream_abort(group, 0, "Hashtype invalid or not supported here");
        return 0;
    }
    keyextype = (encinfo->keyextype_sigtype & 0xF0) >> 4;
    sigtype = encinfo->keyextype_sigtype & 0x0F;
    if (((sigtype != SIG_HMAC) && (sigtype != SIG_KEYEX) &&
                (sigtype != SIG_AUTHENC)) ||
            ((sigtype == SIG_AUTHENC) && (!is_auth_enc(encinfo->keytype)))) {
        glog1(group, "Invalid sigtype specified");
        send_upstream_abort(group, 0, "Invalid sigtype specified");
        return 0;
    }
    if ((keyextype != KEYEX_RSA) && (keyextype != KEYEX_ECDH_RSA) &&
            (keyextype != KEYEX_ECDH_ECDSA)) {
        glog1(group, "Invalid keyextype specified");
        send_upstream_abort(group, 0, "Invalid keyextype specified");
        return 0;
    }
    group->keyextype = keyextype;
    group->keytype = encinfo->keytype;
    group->hashtype = encinfo->hashtype;
    group->sigtype = sigtype;
    group->client_auth = ((encinfo->flags & FLAG_CLIENT_AUTH) != 0);

    if (!verify_fingerprint(server_fp, server_fp_count, keys,
                            ntohs(encinfo->keylen), group, group->src_id)) {
        glog1(group, "Failed to verify server key fingerprint");
        send_upstream_abort(group,0, "Failed to verify server key fingerprint");
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
            glog1(group, "Failed to load server public key");
            send_upstream_abort(group, 0, "Failed to load server public key");
            return 0;
        }
        group->server_pubkeylen = RSA_keylen(group->server_pubkey.rsa);
        for (i = 0; i < key_count; i++) {
            if ((privkey_type[i] == KEYBLOB_RSA) &&
                    (group->server_pubkeylen) == RSA_keylen(privkey[i].rsa)) {
                    group->proxy_privkey = privkey[i];
                    group->proxy_privkeylen = RSA_keylen(privkey[i].rsa);
                    break;
            }
        }
    } else {
        if (!import_EC_key(&group->server_pubkey.ec, keys,
                           ntohs(encinfo->keylen), 0)) {
            glog1(group, "Failed to load server public key");
            send_upstream_abort(group, 0, "Failed to load server public key");
            return 0;
        }
        group->server_pubkeylen = ECDSA_siglen(group->server_pubkey.ec);
        for (i = 0; i < key_count; i++) {
            if ((privkey_type[i] == KEYBLOB_EC) &&
                    (get_EC_curve(group->server_pubkey.ec) ==
                        get_EC_curve(privkey[i].ec))) {
                group->proxy_privkey = privkey[i];
                group->proxy_privkeylen = ECDSA_siglen(privkey[i].ec);
                break;
            }
        }
    }
    if (!group->proxy_privkey.key) {
        glog1(group, "No proxy key compatible with server key");
        send_upstream_abort(group,0, "No proxy key compatible with server key");
        return 0;
    }
    if ((group->keyextype == KEYEX_ECDH_ECDSA) ||
            (group->keyextype == KEYEX_ECDH_RSA)) {
        unsigned char *sigcopy;
        int siglen;
        unsigned char *dhblob = keys + ntohs(encinfo->keylen);
        unsigned char *sig = dhblob + ntohs(encinfo->dhlen);

        if (!import_EC_key(&group->server_dhkey.ec, dhblob,
                           ntohs(encinfo->dhlen), 1)) {
            glog1(group, "Failed to load server public ECDH key");
            send_upstream_abort(group, 0,
                    "Failed to load server public ECDH key");
            return 0;
        }

        if (proxy_type == RESPONSE_PROXY) {
            if (get_EC_curve(group->server_pubkey.ec) ==
                    get_EC_curve(dhkey.ec)) {
                group->proxy_dhkey = dhkey;
            } else {
                glog1(group, "Proxy ECDH key not compatible with server key");
                send_upstream_abort(group, 0,
                        "Proxy ECDH key not compatible with server key");
                return 0;
            }
        } else {
            group->proxy_dhkey.ec =
                    gen_EC_key(get_EC_curve(group->server_dhkey.ec), 1, NULL);
            if (!group->proxy_dhkey.key) {
                glog0(group, "Failed to generate proxy ECDH key");
                send_upstream_abort(group, 0,
                        "Failed to generate proxy ECDH key");
                return 0;
            }
        }

        siglen = ntohs(encinfo->siglen);
        sigcopy = safe_calloc(siglen, 1);
        memcpy(sigcopy, sig, siglen);
        memset(sig, 0, siglen);
        if (keytype == KEYBLOB_RSA) {
            if (!verify_RSA_sig(group->server_pubkey.rsa, group->hashtype,
                                packet, packetlen, sigcopy, siglen)) {
                glog1(group, "Signature verification failed");
                send_upstream_abort(group, 0, "Signature verification failed");
                free(sigcopy);
                return 0;
            }
        } else {
            if (!verify_ECDSA_sig(group->server_pubkey.ec, group->hashtype,
                                  packet, packetlen, sigcopy, siglen)) {
                glog1(group, "Signature verification failed");
                send_upstream_abort(group, 0, "Signature verification failed");
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
int read_announce(struct pr_group_list_t *group, unsigned char *packet,
                  const union sockaddr_u *src, int packetlen)
{
    struct uftp_h *header;
    struct announce_h *announce;
    struct enc_info_he *encinfo;
    uint8_t *publicmcast, *privatemcast;
    uint8_t *he;
    unsigned int iplen, extlen;

    header = (struct uftp_h *)packet;
    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    encinfo = NULL;

    group->version = header->version;
    group->group_id = ntohl(header->group_id);
    group->group_inst = header->group_inst;
    group->up_addr = *src;
    group->src_id = header->src_id;
    group->grtt = unquantize_grtt(header->grtt);
    group->robust = announce->robust;
    group->cc_type = announce->cc_type;
    group->gsize = unquantize_gsize(header->gsize);
    group->blocksize = ntohs(announce->blocksize);
    iplen = ((announce->flags & FLAG_IPV6) != 0) ?
                sizeof(struct in6_addr) : sizeof(struct in_addr);
    publicmcast = ((uint8_t *)announce) + sizeof(struct announce_h);
    privatemcast = publicmcast + iplen;
    if ((announce->flags & FLAG_IPV6) != 0) {
        group->publicmcast.sin6.sin6_family = AF_INET6;
        group->privatemcast.sin6.sin6_family = AF_INET6;
        memcpy(&group->publicmcast.sin6.sin6_addr.s6_addr, publicmcast, iplen);
        memcpy(&group->privatemcast.sin6.sin6_addr.s6_addr, privatemcast,iplen);
        group->publicmcast.sin6.sin6_port = htons(out_port);
        group->privatemcast.sin6.sin6_port = htons(out_port);
    } else {
        group->publicmcast.sin.sin_family = AF_INET;
        group->privatemcast.sin.sin_family = AF_INET;
        memcpy(&group->publicmcast.sin.sin_addr.s_addr, publicmcast, iplen);
        memcpy(&group->privatemcast.sin.sin_addr.s_addr, privatemcast, iplen);
        group->publicmcast.sin.sin_port = htons(out_port);
        group->privatemcast.sin.sin_port = htons(out_port);
    }

    if ((announce->hlen * 4U) < sizeof(struct announce_h) + (2U * iplen)) {
        glog1(group, "Rejecting ANNOUNCE from %08X: invalid header size",
                     ntohl(group->src_id));
        send_upstream_abort(group, 0, "Invalid header size");
        return 0;
    }
    if ((announce->hlen * 4U) > sizeof(struct announce_h) + (2U * iplen)) {
        he = (uint8_t *)announce + sizeof(struct announce_h) + (2U * iplen);
        if (*he == EXT_ENC_INFO) {
            encinfo = (struct enc_info_he *)he;
            extlen = encinfo->extlen * 4U;
            if ((extlen > ((announce->hlen * 4U) -
                            sizeof(struct announce_h))) ||
                    (extlen < sizeof(struct enc_info_he)) ||
                    (extlen != (sizeof(struct enc_info_he) +
                                ntohs(encinfo->keylen) + ntohs(encinfo->dhlen) +
                                ntohs(encinfo->siglen)))) {
                glog1(group, "Rejecting ANNOUNCE from %08X: "
                             "invalid extension size", ntohl(group->src_id));
                send_upstream_abort(group, 0, "Invalid extension size");
                return 0;
            }
        }
    }

    if ((encinfo != NULL) && (proxy_type != SERVER_PROXY)) {
        if (!read_announce_encryption(group, encinfo, packet, packetlen)) {
            return 0;
        }
    } else {
        group->keyextype = KEYEX_NONE;
        group->keytype = KEY_NONE;
        group->hashtype = HASH_NONE;
        group->sigtype = SIG_NONE;
        group->client_auth = 0;
    }

    gettimeofday(&group->phase_expire_time, NULL);
    if (group->robust * group->grtt < 1.0) {
        add_timeval_d(&group->phase_expire_time, 1.0);
    } else {
        add_timeval_d(&group->phase_expire_time, group->robust * group->grtt);
    }

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

    return 1;
}

/**
 * Inserts the proxy's public keys into an ANNOUNCE
 * Returns 1 on success, 0 on fail
 */
int insert_pubkey_in_announce(struct pr_group_list_t *group,
                              unsigned char *packet, int packetlen)
{
    struct announce_h *announce;
    struct enc_info_he *encinfo;
    unsigned char *keyblob, *dhkeyblob;
    uint16_t bloblen;
    unsigned int iplen;

    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));
    iplen = ((announce->flags & FLAG_IPV6) != 0) ? 16 : 4;
    encinfo = (struct enc_info_he *)
            ((uint8_t *)announce + sizeof(struct announce_h) + (2U * iplen));
    keyblob = ((unsigned char *)encinfo + sizeof(struct enc_info_he));
    dhkeyblob = keyblob + ntohs(encinfo->keylen);

    if ((group->keytype != KEY_NONE) && (proxy_type == CLIENT_PROXY)) {
        // Plug in proxy's public key for server's
        if ((group->keyextype == KEYEX_RSA) ||
                (group->keyextype == KEYEX_ECDH_RSA)) {
            if (!export_RSA_key(group->proxy_privkey.rsa, keyblob, &bloblen)) {
                glog0(group, "Error exporting proxy public key");
                return 0;
            }
        } else {
            if (!export_EC_key(group->proxy_privkey.ec, keyblob, &bloblen)) {
                glog0(group, "Error exporting proxy public key");
                return 0;
            }
        }
        if (bloblen != ntohs(encinfo->keylen)) {
            glog0(group, "Incorrect exported proxy key size");
            return 0;
        }
        if ((group->keyextype == KEYEX_ECDH_ECDSA) ||
                (group->keyextype == KEYEX_ECDH_RSA)) {
            if (!export_EC_key(group->proxy_dhkey.ec, dhkeyblob, &bloblen)) {
                glog0(group, "Error exporting proxy ECDH public key");
                return 0;
            }
            if (bloblen != ntohs(encinfo->dhlen)) {
                glog0(group, "Incorrect exported proxy ECDH key size");
                return 0;
            }
        }
    }
    return 1;
}

/**
 * Handles an incoming ANNOUNCE message from a server.
 * Sets up encryption if specified and forwards message.
 */
void handle_announce(struct pr_group_list_t *group,
                     const union sockaddr_u *src, unsigned char *packet,
                     unsigned packetlen)
{
    struct uftp_h *header;
    struct announce_h *announce;
    char pubname[INET6_ADDRSTRLEN], privname[INET6_ADDRSTRLEN];
    int rval;

    header = (struct uftp_h *)packet;
    announce = (struct announce_h *)(packet + sizeof(struct uftp_h));

    if ((packetlen < sizeof(struct uftp_h) + (announce->hlen * 4)) ||
            ((announce->hlen * 4) < sizeof(struct announce_h))) {
        glog1(group, "Rejecting ANNOUNCE from %08X: "
                "invalid message size", ntohl(header->src_id));
        return;
    }

    if (group == NULL) {
        if ((group = find_open_slot()) == NULL ) {
            log1(ntohl(header->group_id), group->group_inst, 0,
                    "Error: maximum number of incoming files exceeded: %d\n",
                    MAXLIST);
            return;
        }
        if (!read_announce(group, packet, src, packetlen)) {
            return;
        }
        if ((rval = getnameinfo((struct sockaddr *)&group->publicmcast,
                family_len(group->publicmcast), pubname, sizeof(pubname),
                NULL, 0, NI_NUMERICHOST)) != 0) {
            glog1(group, "getnameinfo failed: %s", gai_strerror(rval));
        }
        if ((rval = getnameinfo((struct sockaddr *)&group->privatemcast,
                family_len(group->privatemcast), privname, sizeof(privname),
                NULL, 0, NI_NUMERICHOST)) != 0) {
            glog1(group, "getnameinfo failed: %s", gai_strerror(rval));
        }

        glog2(group, "Received request from %08X", ntohl(group->src_id));
        glog2(group, "Using public multicast address %s", pubname);
        glog2(group, "Using private multicast address %s",privname);

        if (!addr_blank(&group->privatemcast) && (proxy_type != CLIENT_PROXY)) {
            if (server_fp_count) {
                if (!is_multicast(&group->privatemcast, 1)) {
                    glog1(group,"Invalid source specific multicast address: %s",
                                privname);
                    send_upstream_abort(group, 0,
                            "Invalid source specific multicast address");
                    return;
                }
            } else {
                if (!is_multicast(&group->privatemcast, 0)) {
                    glog1(group, "Invalid multicast address: %s", privname);
                    send_upstream_abort(group, 0, "Invalid multicast address");
                    return;
                }
            }
            if (!other_mcast_users(group)) {
                if (!multicast_join(listener, group->group_id,
                        &group->privatemcast, m_interface, interface_count,
                        server_fp, server_fp_count)) {
                    send_upstream_abort(group,0,"Error joining multicast group");
                    return;
                }
            }
            group->multi_join = 1;
        }
        group->phase = PR_PHASE_REGISTERED;
    }

    if (insert_pubkey_in_announce(group, packet, packetlen)) {
        forward_message(group, src, packet, packetlen);
    }
}

/**
 * Handles in incoming REG_CONF from a server when encryption is enabled.
 * Upon receiving this message, mark all clients listed as having received.
 * If we got a KEYINFO from the server, send a KEYINFO to all marked clients.
 */
void handle_regconf(struct pr_group_list_t *group, const unsigned char *message,
                    unsigned meslen)
{
    const struct regconf_h *regconf;
    const uint32_t *addrlist;
    int hostidx, idx, addrcnt;
    struct pr_destinfo_t *dest;

    regconf = (const struct regconf_h *)message;
    addrlist = (const uint32_t *)(message + (regconf->hlen * 4));
    addrcnt = (meslen - (regconf->hlen * 4)) / 4;

    if ((meslen < (regconf->hlen * 4U)) ||
            ((regconf->hlen * 4U) < sizeof(struct regconf_h))) {
        glog1(group, "Rejecting REG_CONF from server: invalid message size");
        return;
    }

    glog2(group, "Received REG_CONF");
    for (idx = 0; idx < addrcnt; idx++) {
        hostidx = find_client(group, addrlist[idx]);
        if (hostidx != -1) {
            dest = &group->destinfo[hostidx];
            glog2(group, "  for %s", dest->name);
            if (dest->state != PR_CLIENT_READY) {
                dest->state = PR_CLIENT_CONF;
            }
        }
    }
    if (group->phase == PR_PHASE_READY) {
        send_keyinfo(group, addrlist, addrcnt);
    }
    set_timeout(group, 0, 0);

}

/**
 * Handles an incoming KEYINFO message from a server.
 * Expected in response to a REGISTER when encryption is enabled.  The proxy
 * itself should be specified, not any clients behind it.
 */
void handle_keyinfo(struct pr_group_list_t *group, unsigned char *message,
                    unsigned meslen, uint32_t src_id)
{
    struct keyinfo_h *keyinfo_hdr;
    struct destkey *keylist;
    unsigned explen, declen;
    int i, keyidx, len, keycount, unauth_keytype, unauth_keylen, unauth_ivlen;
    uint8_t decgroupmaster[MASTER_LEN], *prf_buf, *iv;
    uint64_t ivctr;

    keyinfo_hdr = (struct keyinfo_h *)message;
    keylist = (struct destkey *)(message + (keyinfo_hdr->hlen * 4));
    keycount = (meslen - (keyinfo_hdr->hlen * 4)) / sizeof(struct destkey);

    if ((meslen < (keyinfo_hdr->hlen * 4U)) ||
            ((keyinfo_hdr->hlen * 4U) < sizeof(struct keyinfo_h))) {
        glog1(group, "Rejecting KEYINFO from server: invalid message size");
        return;
    }
    if (group->keytype == KEY_NONE) {
        glog1(group, "Rejecting KEYINFO from server: encryption not enabled");
        return;
    }

    for (i = 0, keyidx = -1; (i < keycount) && (keyidx == -1); i++) {
        if (uid == keylist[i].dest_id) {
            keyidx = i;
            break;
        }
    }

    // Don't use a cipher in an authentication mode to decrypt the group master
    unauth_keytype = unauth_key(group->keytype);
    get_key_info(unauth_keytype, &unauth_keylen, &unauth_ivlen);
    if (keyidx != -1) {
        glog2(group, "Received KEYINFO");
        if (group->phase != PR_PHASE_REGISTERED) {
            // We already got the KEYINFO, so no need to reprocess.
            // Just resend the INFO_ACK and reset the timeout
            send_keyinfo_ack(group);
            return;
        }
        iv = safe_calloc(unauth_ivlen, 1);
        ivctr = ntohl(keyinfo_hdr->iv_ctr_lo);
        ivctr |= (uint64_t)ntohl(keyinfo_hdr->iv_ctr_hi) << 32;
        build_iv(iv, group->salt, unauth_ivlen, uftp_htonll(ivctr), src_id);
        if (!decrypt_block(unauth_keytype, iv, group->key, NULL, 0,
                    keylist[keyidx].groupmaster, MASTER_LEN,
                    decgroupmaster, &declen) ||
                (declen != MASTER_LEN - 1)) {
            glog1(group, "Decrypt failed for group master");
            send_upstream_abort(group, 0, "Decrypt failed for group master");
            free(iv);
            return;
        }
        free(iv);
        group->groupmaster[0] = group->version;
        memcpy(&group->groupmaster[1], decgroupmaster, declen);

        explen = group->keylen + SALT_LEN + group->hmaclen;
        prf_buf = safe_calloc(explen + group->hmaclen, 1);
        PRF(group->hashtype, explen, group->groupmaster,
                sizeof(group->groupmaster), "key expansion",
                group->rand1, sizeof(group->rand1), prf_buf, &len);
        memcpy(group->grouphmackey, prf_buf, group->hmaclen);
        memcpy(group->groupkey, prf_buf + group->hmaclen, group->keylen);
        memcpy(group->groupsalt, prf_buf + group->hmaclen + group->keylen,
                SALT_LEN);

        free(prf_buf);
        group->phase = PR_PHASE_READY;
        // Respond to server, then send any pending REG_CONFs as KEYINFO
        send_keyinfo_ack(group);
        send_keyinfo(group, NULL, 0);
    }
}

/**
 * Sends a REGISTER to the server for all pending clients.
 */
void send_register(struct pr_group_list_t *group, int pendidx)
{
    struct uftp_h *header;
    struct register_h *reg;
    unsigned char *buf, *keydata;
    uint32_t *addrlist;
    unsigned int len, meslen, destcount;
    struct timeval now, send_time;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    reg = (struct register_h *)(buf + sizeof(struct uftp_h));
    keydata = (unsigned char *)reg + sizeof(struct register_h);

    set_uftp_header(header, REGISTER, group);
    reg->func = REGISTER;
    if (group->keytype != KEY_NONE) {
        memcpy(reg->rand2, group->rand2, RAND_LEN);
        if (group->keyextype == KEYEX_RSA) {
            if (!RSA_encrypt(group->server_pubkey.rsa, group->premaster,
                             group->premaster_len, keydata, &len)) {
                glog0(group, "Error encrypting premaster secret");
                send_upstream_abort(group, 0,
                        "Error encrypting premaster secret");
                free(buf);
                return;
            }
        } else {
            uint16_t keylen;
            if (!export_EC_key(group->proxy_dhkey.ec, keydata, &keylen)) {
                glog0(group, "Error exporting ECDH public key");
                send_upstream_abort(group,0, "Error exporting ECDH public key");
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
    if (cmptimestamp(now, group->pending[pendidx].rx_tstamp) <= 0) {
        send_time = group->pending[pendidx].tstamp;
    } else {
        send_time = add_timeval(group->pending[pendidx].tstamp,
                diff_timeval(now, group->pending[pendidx].rx_tstamp));
    }
    reg->tstamp_sec = htonl((uint32_t)send_time.tv_sec);
    reg->tstamp_usec = htonl((uint32_t)send_time.tv_usec);

    addrlist = (uint32_t *)(keydata + len);
    reg->hlen = (sizeof(struct register_h) + len) / 4;
    destcount = load_pending(group, pendidx, REGISTER, addrlist,
                             max_msg_dest(group, REGISTER, reg->hlen * 4));
    meslen = sizeof(struct uftp_h) + (reg->hlen * 4) + (destcount * 4);

    if (nb_sendto(listener, buf, meslen, 0, (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending REGISTER");
    } else {
        glog2(group, "REGISTER sent");
    }

    if (group->client_auth) {
        send_clientkey(group);
    }
    set_timeout(group, 1, 0);
    free(buf);
}

/**
 * Sends a CLIENT_KEY message to the server if requested.
 */
void send_clientkey(struct pr_group_list_t *group)
{
    struct uftp_h *header;
    struct client_key_h *client_key;
    unsigned char *buf, *keyblob, *verify;
    uint8_t *verifydata;
    unsigned int siglen, meslen;
    uint16_t bloblen;
    int verifylen;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    client_key = (struct client_key_h *)(buf + sizeof(struct uftp_h));
    keyblob = (unsigned char *)client_key + sizeof(struct client_key_h);

    verifydata = build_verify_data(group, -1, &verifylen, 0);
    if (!verifydata) {
        glog0(group, "Error getting verify data");
        send_upstream_abort(group, 0, "Error getting verify data");
        goto end;
    }

    set_uftp_header(header, CLIENT_KEY, group);

    client_key->func = CLIENT_KEY;
    if ((group->keyextype == KEYEX_RSA) ||
            (group->keyextype == KEYEX_ECDH_RSA)) {
        if (!export_RSA_key(group->proxy_privkey.rsa, keyblob, &bloblen)) {
            glog0(group, "Error exporting public key");
            send_upstream_abort(group, 0, "Error exporting public key");
            goto end;
        }
        verify = keyblob + bloblen;
        if (!create_RSA_sig(group->proxy_privkey.rsa, group->hashtype,
                            verifydata, verifylen, verify, &siglen) ||
                    (siglen > group->proxy_privkeylen)) {
            glog0(group, "Error signing verify data");
            send_upstream_abort(group, 0, "Error signing verify data");
            goto end;
        }
    } else {
        if (!export_EC_key(group->proxy_privkey.ec, keyblob, &bloblen)) {
            glog0(group, "Error exporting public key");
            send_upstream_abort(group, 0, "Error exporting public key");
            goto end;
        }
        verify = keyblob + bloblen;
        if (!create_ECDSA_sig(group->proxy_privkey.ec, group->hashtype,
                              verifydata, verifylen, verify, &siglen)) {
            glog0(group, "Error signing verify data");
            send_upstream_abort(group, 0, "Error signing verify data");
            goto end;
        }
    }

    client_key->bloblen = htons(bloblen);
    client_key->siglen = htons(siglen);
    client_key->hlen = (sizeof(struct client_key_h) + bloblen + siglen) / 4;

    meslen = sizeof(struct uftp_h) + (client_key->hlen * 4);
    if (nb_sendto(listener, buf, meslen, 0, (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending CLIENT_KEY");
    } else {
        glog2(group, "CLIENT_KEY sent");
    }

end:
    free(verifydata);
    free(buf);
}

/**
 * Sends an KEYINFO_ACK to the server in response to a KEYINFO
 */
void send_keyinfo_ack(struct pr_group_list_t *group)
{
    unsigned char *buf, *encrypted;
    struct uftp_h *header;
    struct keyinfoack_h *keyinfo_ack;
    unsigned char *verifydata, *verify_hash, *verify_val;
    unsigned int payloadlen, hashlen;
    int verifylen, len, enclen;

    buf = safe_calloc(MAXMTU, 1);

    header = (struct uftp_h *)buf;
    keyinfo_ack = (struct keyinfoack_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, KEYINFO_ACK, group);
    keyinfo_ack->func = KEYINFO_ACK;
    keyinfo_ack->hlen = sizeof(struct keyinfoack_h) / 4;

    verifydata = build_verify_data(group, -1, &verifylen, 1);
    if (!verifydata) {
        glog0(group, "Error getting verify data");
        send_upstream_abort(group, 0, "Error getting verify data");
        free(buf);
        return;
    }

    verify_hash = safe_calloc(group->hmaclen, 1);
    verify_val = safe_calloc(VERIFY_LEN + group->hmaclen, 1);
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
    if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
            group->keytype, group->groupkey, group->groupsalt, &group->ivctr,
            group->ivlen, group->hashtype, group->grouphmackey, group->hmaclen,
            group->sigtype, group->keyextype, group->proxy_privkey,
            group->proxy_privkeylen)) {
        glog0(group, "Error encrypting KEYINFO_ACK");
        free(buf);
        return;
    }
    payloadlen = enclen + sizeof(struct uftp_h);

    if (nb_sendto(listener, encrypted, payloadlen, 0,
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        gsockerror(group, "Error sending KEYINFO_ACK");
    } else {
        glog2(group, "KEYINFO_ACK sent");
    }
    set_timeout(group, 0, 0);
    free(encrypted);
    free(buf);
}

/**
 * Sends a FILEINFO_ACK to the server for all pending clients
 */
void send_fileinfo_ack(struct pr_group_list_t *group, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct fileinfoack_h *fileinfo_ack;
    struct pr_pending_info_t *pending;
    unsigned int payloadlen;
    int destcount, enclen;
    uint32_t *addrlist;
    struct timeval now, send_time;

    buf = safe_calloc(MAXMTU, 1);

    pending = &group->pending[pendidx];

    header = (struct uftp_h *)buf;
    fileinfo_ack = (struct fileinfoack_h *)(buf + sizeof(struct uftp_h));
    addrlist =(uint32_t *)((char *)fileinfo_ack + sizeof(struct fileinfoack_h));

    payloadlen = sizeof(struct fileinfoack_h);
    set_uftp_header(header, FILEINFO_ACK, group);
    fileinfo_ack->func = FILEINFO_ACK;
    fileinfo_ack->hlen = sizeof(struct fileinfoack_h) / 4;
    fileinfo_ack->file_id = htons(pending->file_id);
    if (pending->partial) {
        fileinfo_ack->flags |= FLAG_PARTIAL;
    }

    gettimeofday(&now, NULL);
    if (cmptimestamp(now, group->pending[pendidx].rx_tstamp) <= 0) {
        send_time = group->pending[pendidx].tstamp;
    } else {
        send_time = add_timeval(group->pending[pendidx].tstamp,
                diff_timeval(now, group->pending[pendidx].rx_tstamp));
    }
    fileinfo_ack->tstamp_sec = htonl((uint32_t)send_time.tv_sec);
    fileinfo_ack->tstamp_usec = htonl((uint32_t)send_time.tv_usec);

    destcount = load_pending(group, pendidx, FILEINFO_ACK, addrlist,
                    max_msg_dest(group, FILEINFO_ACK, fileinfo_ack->hlen * 4));
    payloadlen += destcount * sizeof(uint32_t);

    if (group->keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
                group->keytype, group->groupkey, group->groupsalt,&group->ivctr,
                group->ivlen, group->hashtype, group->grouphmackey,
                group->hmaclen, group->sigtype, group->keyextype,
                group->proxy_privkey, group->proxy_privkeylen)) {
            log0(group->group_id, group->group_inst, pending->file_id,
                    "Error encrypting FILEINFO_ACK");
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
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->group_inst, pending->file_id,
                  "Error sending FILEINFO_ACK");
    } else {
        log2(group->group_id, group->group_inst, pending->file_id,
                "FILEINFO_ACK sent");
    }
    set_timeout(group, 1, 0);
    free(encrypted);
    free(buf);
}

/**
 * Counts the pending naks for the given group
 */
int count_naks(struct pr_group_list_t *group, int pendidx)
{
    unsigned nak_count, i;

    for (nak_count = 0, i = 0; i < group->blocksize * 8; i++) {
        if ((group->pending[pendidx].naklist[i >> 3] & (1 << (i & 7))) != 0) {
            nak_count++;
        }
    }
    // Highly verbose debugging -- print aggregate NAKs before sending
    if (log_level >= 5) {
        for (i = 0; i < group->blocksize; i++) {
            sclog5("%02X ", group->pending[pendidx].naklist[i]);
            if (i % 25 == 24) slog5("");
        }
        slog5("");
    }
    return nak_count;
}

/**
 * Sends a STATUS to the server for all pending clients.
 */
void send_status(struct pr_group_list_t *group, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct status_h *status;
    unsigned char *sent_naks;
    struct pr_pending_info_t *pending;
    struct pr_destinfo_t *dest;
    int hostidx, payloadlen, enclen, nak_count;

    buf = safe_calloc(MAXMTU, 1);
    pending = &group->pending[pendidx];

    // Since a STATUS doesn't contain a host list, we do this simplified
    // cleanup instead of calling load_pending
    for (hostidx = 0; hostidx < group->destcount; hostidx++) {
        dest = &group->destinfo[hostidx];
        if (dest->pending == pendidx) {
            dest->pending = -1;
        }
    }
    group->pending[pendidx].count = 0;
    group->pending[pendidx].msg = 0;

    header = (struct uftp_h *)buf;
    status = (struct status_h *)(buf + sizeof(struct uftp_h));

    nak_count = count_naks(group, pendidx);
    set_uftp_header(header, STATUS, group);
    status->func = STATUS;
    status->hlen = sizeof(struct status_h) / 4;
    status->file_id = htons(pending->file_id);
    status->section = htons(pending->section);
    payloadlen = group->blocksize;
    sent_naks = (unsigned char *)status + sizeof(struct status_h);
    memcpy(sent_naks, pending->naklist, payloadlen);
    memset(pending->naklist, 0, payloadlen);

    payloadlen += sizeof(struct status_h);
    if (group->keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
                group->keytype, group->groupkey, group->groupsalt,&group->ivctr,
                group->ivlen, group->hashtype, group->grouphmackey,
                group->hmaclen, group->sigtype, group->keyextype,
                group->proxy_privkey, group->proxy_privkeylen)) {
            log0(group->group_id, group->group_inst, pending->file_id,
                    "Error encrypting STATUS");
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
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->group_inst, pending->file_id,
                "Error sending STATUS");
    } else {
        log2(group->group_id, group->group_inst, pending->file_id,
                "Sent %d NAKs for section %d", nak_count, pending->section);
    }
    set_timeout(group, 1, 0);

    free(buf);
    free(encrypted);
}

/**
 * Sends a COMPLETE to the server for all pending clients.
 */
void send_complete(struct pr_group_list_t *group, int pendidx)
{
    unsigned char *buf, *encrypted, *outpacket;
    struct uftp_h *header;
    struct complete_h *complete;
    uint32_t *addrlist;
    struct pr_pending_info_t *pending;
    int payloadlen, destcount, enclen;

    buf = safe_calloc(MAXMTU, 1);
    pending = &group->pending[pendidx];

    header = (struct uftp_h *)buf;
    complete = (struct complete_h *)(buf + sizeof(struct uftp_h));
    addrlist = (uint32_t *)((char *)complete + sizeof(struct complete_h));

    set_uftp_header(header, COMPLETE, group);
    complete->func = COMPLETE;
    complete->hlen = sizeof(struct complete_h) / 4;
    complete->file_id = htons(pending->file_id);
    complete->status = pending->comp_status;

    destcount = load_pending(group, pendidx, COMPLETE, addrlist,
                             max_msg_dest(group, COMPLETE, complete->hlen * 4));
    payloadlen = sizeof(struct complete_h) + (destcount * sizeof(uint32_t));

    if (group->keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen,
                group->keytype, group->groupkey, group->groupsalt,&group->ivctr,
                group->ivlen, group->hashtype, group->grouphmackey,
                group->hmaclen, group->sigtype, group->keyextype,
                group->proxy_privkey, group->proxy_privkeylen)) {
            log0(group->group_id, group->group_inst, pending->file_id,
                    "Error encrypting COMPLETE");
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
               (struct sockaddr *)&group->up_addr,
               family_len(group->up_addr)) == SOCKET_ERROR) {
        sockerror(group->group_id, group->group_inst, pending->file_id,
                "Error sending COMPLETE");
    } else {
        log2(group->group_id, group->group_inst, pending->file_id,
                "Sent COMPLETE");
    }
    set_timeout(group, 1, 0);

    free(buf);
    free(encrypted);
}

