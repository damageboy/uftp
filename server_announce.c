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

#else  // if WINDOWS

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_common.h"
#include "server_announce.h"

/**
 * Sets the fields in a EXT_ENC_INFO extension for transmission.
 * Returns the number of bytes set, or 0 on error.
 */
int set_enc_info(const struct finfo_t *finfo, struct enc_info_he *encinfo)
{
    unsigned char *keyblob;
    uint16_t bloblen;
    int extlen;

    keyblob = ((uint8_t *)encinfo + sizeof(struct enc_info_he));

    encinfo->exttype = EXT_ENC_INFO;
    encinfo->keyextype_sigtype = (keyextype & 0x0F) << 4;
    encinfo->keyextype_sigtype |= (sigtype & 0x0F);
    encinfo->keytype = keytype;
    encinfo->hashtype = hashtype;
    if (client_auth) {
        encinfo->flags |= FLAG_CLIENT_AUTH;
    }
    memcpy(encinfo->rand1, rand1, sizeof(rand1));
    if ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) {
        if (!export_RSA_key(privkey.rsa, keyblob, &bloblen)) {
            glog0(finfo, "Error exporting server public key");
            return 0;
        }
    } else {
        if (!export_EC_key(privkey.ec, keyblob, &bloblen)) {
            glog0(finfo, "Error exporting server public key");
            return 0;
        }
    }
    encinfo->keylen = htons(bloblen);
    if ((keyextype == KEYEX_ECDH_RSA) || (keyextype == KEYEX_ECDH_ECDSA)) {
        uint16_t dhlen;
        uint8_t *dhblob = ((uint8_t *)encinfo + sizeof(struct enc_info_he) +
                          ntohs(encinfo->keylen));

        if (!export_EC_key(dhkey.ec, dhblob, &dhlen)) {
            glog0(finfo, "Error exporting server ECDH public key");
            return 0;
        }
        encinfo->dhlen = htons(dhlen);
        if (keyextype == KEYEX_ECDH_RSA) {
            encinfo->siglen = htons(RSA_keylen(privkey.rsa)); 
        } else {
            encinfo->siglen = htons(ECDSA_siglen(privkey.ec)); 
        }
    } else {
        encinfo->dhlen = 0;
        encinfo->siglen = 0;
    }
    
    extlen = sizeof(struct enc_info_he) + ntohs(encinfo->keylen) +
            ntohs(encinfo->dhlen) + ntohs(encinfo->siglen);
    encinfo->extlen = extlen / 4;
    return extlen;
}

/**
 * Send the ANNOUNCE message
 * For open group membership, just send one.  For closed group membership,
 * list as many destinations as will fit and send multiple packets so that
 * each receiver is listed.
 * Returns 1 on success, 0 on fail.
 */
int send_announce(const struct finfo_t *finfo, int attempt, int open)
{
    int packetlen, rval, iplen, extlen;
    unsigned char *buf;
    struct uftp_h *header;
    struct announce_h *announce;
    unsigned char *publicaddr, *privateaddr;
    struct enc_info_he *encinfo;
    struct timeval tv;
    uint32_t *idlist;

    buf = safe_calloc(MAXMTU, 1); 
    if (listen_dest.ss.ss_family == AF_INET6) {
        iplen = sizeof(struct in6_addr);
    } else {
        iplen = sizeof(struct in_addr);
    }
    header = (struct uftp_h *)buf;
    announce = (struct announce_h *)(buf + sizeof(struct uftp_h));
    publicaddr = (unsigned char *)announce + sizeof(struct announce_h);
    privateaddr = publicaddr + iplen;
    encinfo = (struct enc_info_he *)(privateaddr + iplen);

    set_uftp_header(header, ANNOUNCE, finfo->group_id, finfo->group_inst,
                    grtt, destcount);
    announce->func = ANNOUNCE;
    if (sync_mode) {
        announce->flags |= FLAG_SYNC_MODE;
        if (sync_preview) {
            announce->flags |= FLAG_SYNC_PREVIEW;
        }
    }
    announce->robust = robust;
    announce->cc_type = cc_type;
    announce->blocksize = htons(blocksize);
    gettimeofday(&tv, NULL);
    announce->tstamp_sec = htonl(tv.tv_sec);
    announce->tstamp_usec = htonl(tv.tv_usec);
    if (!is_multicast(&listen_dest, 0)) {
        memset(publicaddr, 0, iplen);
        memset(privateaddr, 0, iplen);
    } else if (listen_dest.ss.ss_family == AF_INET6) {
        memcpy(publicaddr, &listen_dest.sin6.sin6_addr.s6_addr, iplen);
        memcpy(privateaddr, &receive_dest.sin6.sin6_addr.s6_addr, iplen);
    } else {
        memcpy(publicaddr, &listen_dest.sin.sin_addr.s_addr, iplen);
        memcpy(privateaddr, &receive_dest.sin.sin_addr.s_addr, iplen);
    }
    if (listen_dest.ss.ss_family == AF_INET6) {
        announce->flags |= FLAG_IPV6;
    }

    if (keytype != KEY_NONE) {
        extlen = set_enc_info(finfo, encinfo);
        if (extlen == 0) {
            glog0(finfo, "Error setting up EXT_ENC_INFO");
            free(buf);
            return 0;
        }
        announce->hlen = (sizeof(struct announce_h) +
                          iplen + iplen + extlen) / 4;
    } else {
        announce->hlen = (sizeof(struct announce_h) + iplen + iplen) / 4;
    }

    idlist = (uint32_t *)((uint8_t *)announce + (announce->hlen * 4));
    if (open) {
        header->seq = htons(send_seq++);
        packetlen = sizeof(struct uftp_h) + (announce->hlen * 4);
        if (!sign_announce(finfo, buf, packetlen)) {
            glog0(finfo, "Error signing ANNOUNCE");
            free(buf);
            return 0;
        }
        glog2(finfo, "Sending ANNOUNCE %d", attempt);
        if (nb_sendto(sock, buf, packetlen, 0, (struct sockaddr *)&listen_dest,
                      family_len(listen_dest)) == SOCKET_ERROR) {
            gsockerror(finfo, "Error sending ANNOUNCE");
            // So we don't spin our wheels...
            sleep(1);
            free(buf);
            return 0;
        }
        free(buf);
        return 1;
    } else {
        rval = send_multiple(finfo, buf, ANNOUNCE, attempt, idlist,
                DEST_MUTE, 0, &listen_dest, 0);
        free(buf);
        return rval;
    }
}

/**
 * Send out REG_CONF messages specifying all registered clients.
 * Sent when encryption is disabled, or if the client is behind a proxy.
 * Returns 1 on success, 0 on fail
 */
int send_regconf(const struct finfo_t *finfo, int attempt, int do_regconf)
{
    int rval;
    unsigned char *buf;
    struct uftp_h *header;
    struct regconf_h *regconf;
    uint32_t *idlist;

    buf = safe_calloc(MAXMTU, 1); 
    header = (struct uftp_h *)buf;
    regconf = (struct regconf_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, REG_CONF, finfo->group_id, finfo->group_inst,
                    grtt, destcount);
    regconf->func = REG_CONF;
    regconf->hlen = sizeof(struct regconf_h) / 4;

    idlist = (uint32_t *)((uint8_t *)regconf + (regconf->hlen * 4));
    rval = send_multiple(finfo, buf, REG_CONF, attempt, idlist, DEST_ACTIVE,
                         0, &receive_dest, do_regconf);
    free(buf);
    return rval;
}

/**
 * Send a KEYINFO message.  Sent during the Announce phase for a group
 * with encryption enabled.
 * Returns 1 on success, 0 on fail.
 */
int send_keyinfo(const struct finfo_t *finfo, int attempt)
{
    unsigned char *buf, *iv;
    struct uftp_h *header;
    struct keyinfo_h *keyinfo;
    struct destkey *keylist;
    unsigned int hsize, payloadlen, len;
    int maxdest, packetcnt, dests, iv_init, i;
    int unauth_keytype, unauth_keylen, unauth_ivlen;

    // Don't use a cipher in an authentication mode to encrypt the group master
    unauth_keytype = unauth_key(keytype);
    get_key_info(unauth_keytype, &unauth_keylen, &unauth_ivlen);

    buf = safe_calloc(MAXMTU, 1);
    iv = safe_calloc(unauth_ivlen, 1);
    header = (struct uftp_h *)buf;
    keyinfo = (struct keyinfo_h *)(buf + sizeof(struct uftp_h));
    keylist = (struct destkey *)((char *)keyinfo + sizeof(struct keyinfo_h));

    set_uftp_header(header, KEYINFO, finfo->group_id, finfo->group_inst,
                    grtt, destcount);
    keyinfo->func = KEYINFO;
    keyinfo->hlen = sizeof(struct keyinfo_h) / 4;
    keylist = (struct destkey *)((uint8_t *)keyinfo + (keyinfo->hlen * 4));

    iv_init = 0;
    hsize = sizeof(struct keyinfo_h);
    maxdest = blocksize / sizeof(struct destkey);
    packetcnt = 1;
    for (i = 0, dests = 0; i < destcount; i++) {
        if (destlist[i].status == DEST_REGISTERED) {
            if (!iv_init) {
                ivctr++;
                keyinfo->iv_ctr_hi =htonl((ivctr & 0xFFFFFFFF00000000LL) >> 32);
                keyinfo->iv_ctr_lo = htonl(ivctr & 0x00000000FFFFFFFFLL);
                iv_init = 1;
            }
            keylist[dests].dest_id = destlist[i].id;
            build_iv(iv, destlist[i].encinfo->salt, unauth_ivlen,
                     uftp_htonll(ivctr), header->src_id);
            if (!encrypt_block(unauth_keytype, iv,destlist[i].encinfo->key,
                               NULL,0, &groupmaster[1], sizeof(groupmaster) - 1,
                               keylist[dests].groupmaster, &len)) {
                glog0(finfo, "Error encrypting KEYINFO for %s",
                             destlist[i].name);
                free(buf);
                free(iv);
                return 0;
            }
            dests++;
        }
        if ((dests >= maxdest) || ((i == destcount - 1) && (dests > 0))) {
            header->seq = htons(send_seq++);
            payloadlen = hsize + (dests * sizeof(struct destkey));
            glog2(finfo, "Sending KEYINFO %d.%d", attempt, packetcnt);
            if (nb_sendto(sock, buf, payloadlen + sizeof(struct uftp_h), 0,
                          (struct sockaddr *)&receive_dest,
                          family_len(receive_dest)) == SOCKET_ERROR) {
                gsockerror(finfo, "Error sending KEYINFO");
                sleep(1);
                free(buf);
                free(iv);
                return 0;
            }
            if (packet_wait) usleep(packet_wait);
            memset(keylist, 0, maxdest * sizeof(struct destkey));
            iv_init = 0;
            dests = 0;
            packetcnt++;
        }
    }
    free(buf);
    free(iv);
    return 1;
}

/**
 * Send a FILEINFO message.  Sent for each individual file.
 * Returns 1 on success, 0 on fail.
 */
int send_fileinfo(const struct finfo_t *finfo, int attempt)
{
    int rval;
    unsigned char *buf;
    struct uftp_h *header;
    struct fileinfo_h *fileinfo;
    struct timeval tv;
    uint32_t *idlist;
    char *filename, *linkname;

    if (strlen(finfo->destfname) > MAXPATHNAME) {
        glog0(finfo, "File name too long: %s", finfo->destfname);
        return 0;
    }

    buf = safe_calloc(MAXMTU, 1); 
    header = (struct uftp_h *)buf;
    fileinfo = (struct fileinfo_h *)(buf + sizeof(struct uftp_h));
    filename = (char *)fileinfo + sizeof(struct fileinfo_h);

    set_uftp_header(header, FILEINFO, finfo->group_id, finfo->group_inst,
                    grtt, destcount);
    fileinfo->func = FILEINFO;
    fileinfo->ftype = finfo->ftype;
    fileinfo->file_id = htons(finfo->file_id);
    fileinfo->namelen = (uint8_t)(0 + ceil(strlen(finfo->destfname) / 4.0));
    fileinfo->lofsize = htonl((finfo->size & 0xFFFFFFFF));
    fileinfo->hifsize = htons((uint16_t)(finfo->size >> 32));
    if (sync_mode) {
        fileinfo->ftstamp = htonl(finfo->tstamp);
    } else {
        fileinfo->ftstamp = 0;
    }
    gettimeofday(&tv, NULL);
    fileinfo->tstamp_sec = htonl(tv.tv_sec);
    fileinfo->tstamp_usec = htonl(tv.tv_usec);

    strncpy(filename, finfo->destfname, MAXPATHNAME);
    if (finfo->ftype == FTYPE_LINK) {
        if (strlen(finfo->linkname) > 
                (unsigned)MAXPATHNAME - (fileinfo->namelen * 4)) {
            glog0(finfo, "Link name too long: %s", finfo->linkname);
            free(buf);
            return 0;
        }
        linkname = filename + (fileinfo->namelen * 4);
        strncpy(linkname, finfo->linkname,
                MAXPATHNAME - (fileinfo->namelen * 4));
        fileinfo->linklen = (uint8_t)(0 + ceil(strlen(finfo->linkname) / 4.0));
    }

    fileinfo->hlen = (sizeof(struct fileinfo_h) + (fileinfo->namelen * 4) +
                     (fileinfo->linklen * 4)) / 4;
    idlist = (uint32_t *)((uint8_t *)fileinfo + (fileinfo->hlen * 4));
    rval = send_multiple(finfo, buf, FILEINFO, attempt, idlist,
            DEST_REGISTERED, (keytype != KEY_NONE), &receive_dest, 0);
    free(buf);
    return rval;
}

/**
 * Adds a registered host to the hostlist.  Returns the list index.
 */
int add_dest_by_addr(uint32_t id, struct finfo_t *finfo,
                     int state, int proxyidx, int isproxy)
{
    snprintf(destlist[destcount].name, sizeof(destlist[destcount].name),
             "0x%08X", ntohl(id));
    destlist[destcount].id = id;
    destlist[destcount].status = state;
    destlist[destcount].proxyidx = proxyidx;
    destlist[destcount].isproxy = isproxy;
    return destcount++;
}

/**
 * When a proxy registers, process the clients the proxy is serving
 */
void add_proxy_dests(struct finfo_t *finfo, const uint32_t *idlist,
                     const union sockaddr_u *su, int clientcnt,
                     int proxyidx, int open, double rtt)
{
    int hostidx, i, dupmsg;

    if (!destlist[proxyidx].isproxy) {
        // True when using open group membership and
        // we get a CLIENT_KEY before the REGSITER for a proxy
        destlist[proxyidx].isproxy = 1;
    }
    for (i = 0; i < clientcnt; i++) {
        dupmsg = 0;
        hostidx = find_client(idlist[i]);
        if (hostidx == -1) {
            if (open) {
                if (destcount == MAXDEST) {
                    glog1(finfo, "Rejecting client %08X: "
                                 "max destinations exceeded", ntohl(idlist[i]));
                    send_abort(finfo, "Max destinations exceeded",
                               su, idlist[i], 0, 0);
                    continue;
                }
                hostidx = add_dest_by_addr(idlist[i], finfo, DEST_ACTIVE,
                                           proxyidx, 0);
            } else {
                glog1(finfo, "Host %08X not in host list", idlist[i]);
                send_abort(finfo, "Not in host list", su, idlist[i], 0, 0);
                continue;
            }
        } else {
            dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
            destlist[hostidx].status = DEST_ACTIVE;
            destlist[hostidx].proxyidx = proxyidx;
        }
        destlist[hostidx].rtt = rtt;
        finfo->deststate[hostidx].conf_sent = 0;
        glog1(finfo, "  For client%s %s", dupmsg ? "+" : "",
                destlist[hostidx].name);
    }
}

/**
 * Returns the verify_data string used in certain messages.  This value
 * is then run through the PRF with the result going into the message
 */
uint8_t *build_verify_data(const struct finfo_t *finfo, int hostidx,
                           int *verifylen)
{
    uint8_t *verifydata;
    uint8_t privatemcast[16];
    uint32_t n_group_id;
    int iplen;

    if (listen_dest.ss.ss_family == AF_INET6) {
        iplen = sizeof(struct in6_addr);
    } else {
        iplen = sizeof(struct in_addr);
    }
    if (!is_multicast(&listen_dest, 0)) {
        memset(privatemcast, 0, iplen);
    } else if (listen_dest.ss.ss_family == AF_INET6) {
        memcpy(privatemcast, &receive_dest.sin6.sin6_addr.s6_addr, iplen);
    } else {
        memcpy(privatemcast, &receive_dest.sin.sin_addr.s_addr, iplen);
    }
    *verifylen = 0;
    if (destlist[hostidx].status == DEST_MUTE) {
        verifydata = safe_calloc(sizeof(finfo->group_id) + iplen +
                sizeof(rand1) + sizeof(destlist[hostidx].encinfo->rand2) +
                sizeof(destlist[hostidx].encinfo->premaster), 1);
    } else {
        verifydata = safe_calloc(sizeof(finfo->group_id) + iplen +
                sizeof(rand1) + sizeof(destlist[hostidx].encinfo->rand2) +
                sizeof(destlist[hostidx].encinfo->premaster) + PUBKEY_LEN +
                sizeof(groupmaster), 1);
    }

    n_group_id = htonl(finfo->group_id);
    memcpy(verifydata, &n_group_id, sizeof(n_group_id));
    *verifylen += sizeof(n_group_id);
    memcpy(verifydata + *verifylen, &privatemcast, iplen);
    *verifylen += iplen;
    memcpy(verifydata + *verifylen, rand1, sizeof(rand1));
    *verifylen += sizeof(rand1);
    memcpy(verifydata + *verifylen, destlist[hostidx].encinfo->rand2,
            sizeof(destlist[hostidx].encinfo->rand2));
    *verifylen += sizeof(destlist[hostidx].encinfo->rand2);
    memcpy(verifydata + *verifylen, destlist[hostidx].encinfo->premaster,
            destlist[hostidx].encinfo->premaster_len);
    *verifylen += destlist[hostidx].encinfo->premaster_len;

    if (destlist[hostidx].status != DEST_MUTE) {
        if (destlist[hostidx].encinfo->pubkey.key) {
            uint16_t bloblen;
            uint8_t *keyblob = verifydata + *verifylen;

            if ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) {
                if (!export_RSA_key(destlist[hostidx].encinfo->pubkey.rsa,
                                    keyblob, &bloblen)) {
                    free(verifydata);
                    return NULL;
                }
            } else {
                if (!export_EC_key(destlist[hostidx].encinfo->pubkey.ec,
                                   keyblob, &bloblen)) {
                    glog0(finfo, "Error exporting server public key");
                    free(verifydata);
                    return NULL;
                }
            }
            *verifylen += bloblen;
        }
        memcpy(verifydata + *verifylen, groupmaster, sizeof(groupmaster));
        *verifylen += sizeof(groupmaster);
    }

    return verifydata;
}

/**
 * Verifies the data in a CLIENT_KEY message signed by the client's public key
 */
int verify_client_key(struct finfo_t *finfo, int hostidx)
{
    uint8_t *verifydata;
    int verifylen;

    // build_verify_data should never fail in this case
    verifydata = build_verify_data(finfo, hostidx, &verifylen);

    if ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) {
        if (!verify_RSA_sig(destlist[hostidx].encinfo->pubkey.rsa, hashtype,
                verifydata, verifylen, destlist[hostidx].encinfo->verifydata,
                destlist[hostidx].encinfo->verifylen)) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                         destlist[hostidx].name);
            free(verifydata);
            return 0;
        }
    } else {
        if (!verify_ECDSA_sig(destlist[hostidx].encinfo->pubkey.ec, hashtype,
                verifydata, verifylen, destlist[hostidx].encinfo->verifydata,
                destlist[hostidx].encinfo->verifylen)) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: verify data mismatch",
                         destlist[hostidx].name);
            free(verifydata);
            return 0;
        }
    }

    destlist[hostidx].status = DEST_REGISTERED;
    free(verifydata);
    return 1;
}

/**
 * For a given client, calculate the master key and do key expansion
 * to determine the symmetric cypher key and IV salt, and hash key
 */
void calculate_client_keys(int hostidx)
{
    unsigned char *seed, *prf_buf;
    int explen, len, seedlen;

    explen = keylen + SALT_LEN + hmaclen;
    seedlen = sizeof(rand1) * 2;
    seed = safe_calloc(seedlen, 1);
    prf_buf = safe_calloc(MASTER_LEN + explen + hmaclen, 1);

    memcpy(seed, rand1, sizeof(rand1));
    memcpy(seed + sizeof(rand1), destlist[hostidx].encinfo->rand2,
            sizeof(destlist[hostidx].encinfo->rand2));
    PRF(hashtype, MASTER_LEN, destlist[hostidx].encinfo->premaster,
            destlist[hostidx].encinfo->premaster_len,
            "master secret", seed, seedlen, prf_buf, &len);
    memcpy(destlist[hostidx].encinfo->master,prf_buf,
            sizeof(destlist[hostidx].encinfo->master));

    PRF(hashtype, explen, destlist[hostidx].encinfo->master, 
            sizeof(destlist[hostidx].encinfo->master), "key expansion",
            seed, seedlen, prf_buf, &len);
    memcpy(destlist[hostidx].encinfo->hmackey, prf_buf, hmaclen);
    memcpy(destlist[hostidx].encinfo->key, prf_buf + hmaclen, keylen);
    memcpy(destlist[hostidx].encinfo->salt, prf_buf + hmaclen + keylen,
            SALT_LEN);

    free(seed);
    free(prf_buf);
}

/**
 * Processes encryption key information received in a REGISTER message
 */
int handle_register_keys(const struct register_h *reg,
                         const unsigned char *keyinfo, struct finfo_t *finfo,
                         int hostidx)
{
    unsigned char premaster[PUBKEY_LEN];
    unsigned int len;

    destlist[hostidx].encinfo = safe_calloc(1, sizeof(struct encinfo_t));
    memcpy(destlist[hostidx].encinfo->rand2, reg->rand2,
           sizeof(destlist[hostidx].encinfo->rand2));
    if (keyextype == KEYEX_RSA) {
        if (!RSA_decrypt(privkey.rsa, keyinfo, ntohs(reg->keyinfo_len),
                         premaster, &len)) {
            glog1(finfo, "Rejecting REGISTER from %s: failed to decrypt "
                         "premaster secret", destlist[hostidx].name);
            return 0;
        }
        if (len != MASTER_LEN) {
            glog1(finfo, "Rejecting REGISTER from %s: decrypted premaster "
                         "secret wrong length", destlist[hostidx].name);
            return 0;
        }
    } else {
        if (!import_EC_key(&destlist[hostidx].encinfo->dhkey.ec, keyinfo,
                           ntohs(reg->keyinfo_len), 1)) {
            glog1(finfo, "Rejecting REGISTER from %s: "
                         "failed to import ECDH key", destlist[hostidx].name);
            return 0;
        }
        if (get_EC_curve(destlist[hostidx].encinfo->dhkey.ec) != ecdh_curve) {
            glog1(finfo, "Rejecting REGISTER from %s: "
                         "invalid curve for ECDH", destlist[hostidx].name);
            return 0;
        }
        if (!get_ECDH_key(destlist[hostidx].encinfo->dhkey.ec, dhkey.ec,
                          premaster, &len)) {
            glog1(finfo, "Rejecting REGISTER from %s: failed to calculate "
                         "premaster secret", destlist[hostidx].name);
            return 0;
        }
    }
    memcpy(destlist[hostidx].encinfo->premaster, premaster, len);
    destlist[hostidx].encinfo->premaster_len = len;
    calculate_client_keys(hostidx);

    if (destlist[hostidx].encinfo->pubkey.key) {
        if (!verify_client_key(finfo, hostidx)) {
            return 0;
        }
    }

    return 1;
}

/**
 * Process an expected REGISTER with open group membership
 */
void handle_open_register(const unsigned char *message, unsigned meslen,
                          struct finfo_t *finfo, const union sockaddr_u *su,
                          uint32_t src, int regconf)
{
    const struct register_h *reg;
    const uint32_t *idlist;
    const unsigned char *enckey;
    int clientcnt, hostidx;
    struct timeval tv1, tv2;

    reg = (const struct register_h *)message;
    enckey = (const unsigned char *)reg + sizeof(struct register_h);
    gettimeofday(&tv2, NULL);

    if (destcount == MAXDEST) {
        glog1(finfo, "Rejecting REGISTER from %08X: "
                     "max destinations exceeded", ntohl(src));
        send_abort(finfo, "Max destinations exceeded", su, src, 0, 0);
        return;
    }
    if ((meslen < (reg->hlen * 4U)) || ((reg->hlen * 4U) <
            sizeof(struct register_h) + ntohs(reg->keyinfo_len))) {
        glog1(finfo, "Rejecting REGISTER from %08X: "
                     "invalid message size", ntohl(src));
        send_abort(finfo, "Invalid message size", su, src, 0, 0);
        return;
    }

    clientcnt = (meslen - (reg->hlen * 4)) / 4;
    hostidx = add_dest_by_addr(src, finfo, DEST_MUTE, -1, (clientcnt > 0));
    if (keytype != KEY_NONE) {
        if (!handle_register_keys(reg, enckey, finfo, hostidx)) {
            return;
        }
    }
    if (regconf) {
        finfo->deststate[hostidx].conf_sent = 0;
    }
    tv1.tv_sec = ntohl(reg->tstamp_sec);
    tv1.tv_usec = ntohl(reg->tstamp_usec);
    destlist[hostidx].rtt = diff_usec(tv2, tv1) / 1000000.0;
    if (destlist[hostidx].rtt < CLIENT_RTT_MIN) {
        destlist[hostidx].rtt = CLIENT_RTT_MIN;
    }
    destlist[hostidx].rtt_measured = 1;
    destlist[hostidx].registered = 1;
    destlist[hostidx].status =
            regconf ? DEST_ACTIVE : (client_auth ? DEST_MUTE : DEST_REGISTERED);
    glog2(finfo, "Received REGISTER from %s %s",
              (clientcnt > 0) ? "proxy" : "client", destlist[hostidx].name);
    if (clientcnt > 0) {
        idlist = (const uint32_t *)(message + (reg->hlen * 4));
        add_proxy_dests(finfo, idlist, su, clientcnt, hostidx, 1,
                        destlist[hostidx].rtt);
    }
    glog3(finfo, "send time = %d.%06d", tv1.tv_sec, tv1.tv_usec);
    glog3(finfo, "rx time = %d.%06d", tv2.tv_sec, tv2.tv_usec);
    glog3(finfo, "  rtt = %.6f", destlist[hostidx].rtt);
}

/**
 * Process an expected REGISTER with closed group membership,
 * or with open group membership if CLIENT_KEY was received first.
 */
void handle_register(const unsigned char *message, unsigned meslen,
                     struct finfo_t *finfo, const union sockaddr_u *su,
                     int hostidx, int regconf, int open)
{
    const struct register_h *reg;
    const uint32_t *idlist;
    const unsigned char *enckey;
    int clientcnt, dupmsg, isproxy;
    struct timeval tv1, tv2;

    reg = (const struct register_h *)message;
    enckey = (const unsigned char *)reg + sizeof(struct register_h);
    gettimeofday(&tv2, NULL);

    if ((meslen < (reg->hlen * 4U)) || ((reg->hlen * 4U) <
            sizeof(struct register_h) + ntohs(reg->keyinfo_len))) {
        glog1(finfo, "Rejecting REGISTER from %s: "
                     "invalid message size", destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", su, destlist[hostidx].id,0,0);
        return;
    }
    clientcnt = (meslen - (reg->hlen * 4)) / 4;
    if ((clientcnt > 0) && (!destlist[hostidx].isproxy) && (!open)) {
        glog1(finfo, "Rejecting REGISTER from %s: specified multiple clients "
                     "but not a proxy", destlist[hostidx].name);
        send_abort(finfo, "specified multiple clients but not a proxy", su,
                   destlist[hostidx].id, 0, 0);
        destlist[hostidx].status = DEST_ABORT;
        return;
    }    
    if (finfo->file_id != 0) {
        glog2(finfo, "Received REGISTER+ from %s", destlist[hostidx].name);
        return;
    }

    if (destlist[hostidx].status == DEST_MUTE) {
        if (keytype != KEY_NONE) {
            if (!handle_register_keys(reg, enckey, finfo, hostidx)) {
                return;
            }
        }
        destlist[hostidx].status = regconf ? DEST_ACTIVE : 
                ((client_auth && (!destlist[hostidx].encinfo->pubkey.key))
                    ? DEST_MUTE : DEST_REGISTERED);
    }
    dupmsg = (destlist[hostidx].registered);
    tv1.tv_sec = ntohl(reg->tstamp_sec);
    tv1.tv_usec = ntohl(reg->tstamp_usec);
    destlist[hostidx].rtt = diff_usec(tv2, tv1) / 1000000.0;
    if (destlist[hostidx].rtt < CLIENT_RTT_MIN) {
        destlist[hostidx].rtt = CLIENT_RTT_MIN;
    }
    destlist[hostidx].rtt_measured = 1;
    destlist[hostidx].registered = 1;
    if (regconf) {
        finfo->deststate[hostidx].conf_sent = 0;
    }
    isproxy = destlist[hostidx].isproxy;
    glog2(finfo, "Received REGISTER%s from %s %s",
            (dupmsg && !isproxy) ? "+" : "",
            (isproxy) ? "proxy" : "client", destlist[hostidx].name);
    if (clientcnt > 0) {
        idlist = (const uint32_t *)(message + (reg->hlen * 4));
        add_proxy_dests(finfo, idlist, su, clientcnt, hostidx, open,
                        destlist[hostidx].rtt);
    }
    glog3(finfo, "send time = %d.%06d", tv1.tv_sec, tv1.tv_usec);
    glog3(finfo, "rx time = %d.%06d", tv2.tv_sec, tv2.tv_usec);
    glog3(finfo, "  rtt = %.6f", destlist[hostidx].rtt);
}

/**
 * Verifies a client's public key fingerprint
 */
int verify_client_fingerprint(const struct finfo_t *finfo,
                              const unsigned char *keyblob,
                              uint16_t bloblen, int hostidx)
{
    unsigned char fingerprint[HMAC_LEN];
    unsigned int fplen;

    if (destlist[hostidx].verified) {
        return 1;
    }

    if (keyblob[0] == KEYBLOB_RSA) {
        if (!import_RSA_key(&destlist[hostidx].encinfo->pubkey.rsa,
                            keyblob, bloblen)) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                         "failed to import key", destlist[hostidx].name);
            return 0;
        }
        destlist[hostidx].encinfo->pubkeylen =
                RSA_keylen(destlist[hostidx].encinfo->pubkey.rsa);
    } else {
        if (!import_EC_key(&destlist[hostidx].encinfo->pubkey.ec,
                           keyblob, bloblen, 0)) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                         "failed to import key", destlist[hostidx].name);
            return 0;
        }
        destlist[hostidx].encinfo->pubkeylen =
                ECDSA_siglen(destlist[hostidx].encinfo->pubkey.ec);
    }

    if (destlist[hostidx].has_fingerprint) {
        hash(HASH_SHA1, keyblob, bloblen, fingerprint, &fplen);
        if (memcmp(destlist[hostidx].keyfingerprint, fingerprint, fplen)) {
            glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                         "key fingerprint mismatch", destlist[hostidx].name);
            if (keyblob[0] == KEYBLOB_RSA) {
                free_RSA_key(destlist[hostidx].encinfo->pubkey.rsa);
            } else {
                free_EC_key(destlist[hostidx].encinfo->pubkey.ec);
            }
            destlist[hostidx].encinfo->pubkey.key = 0;
            destlist[hostidx].encinfo->pubkeylen = 0;
            return 0;
        }
    }

    destlist[hostidx].verified = 1;
    return 1;
}

/**
 * Process an expected CLIENT_KEY with open group membership
 */
void handle_open_clientkey(const unsigned char *message, unsigned meslen,
                           struct finfo_t *finfo, const union sockaddr_u *su,
                           uint32_t src)
{
    const struct client_key_h *clientkey;
    const unsigned char *keyblob, *verify;
    int hostidx;

    clientkey = (const struct client_key_h *)message;
    keyblob = (const unsigned char *)clientkey + sizeof(struct client_key_h);
    verify = keyblob + ntohs(clientkey->bloblen);

    if (destcount == MAXDEST) {
        glog1(finfo, "Rejecting CLIENT_KEY from %08X: "
                     "max destinations exceeded", ntohl(src));
        send_abort(finfo, "Max destinations exceeded", su, src, 0, 0);
        return;
    }
    if ((meslen < (clientkey->hlen * 4U)) ||
            ((clientkey->hlen * 4U) < sizeof(struct client_key_h) +
                ntohs(clientkey->bloblen) + ntohs(clientkey->siglen))) {
        glog1(finfo, "Rejecting CLIENT_KEY from %08X: "
                     "invalid message size", ntohl(src));
        send_abort(finfo, "Invalid message size", su, src, 0, 0);
        return;
    }
    if ((((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) &&
                (keyblob[0] != KEYBLOB_RSA)) ||
            ((keyextype == KEYEX_ECDH_ECDSA) &&
             (keyblob[0] != KEYBLOB_EC))) {
        glog1(finfo, "Rejecting CLIENT_KEY from %08X: "
                     "invalid keyblob type", ntohl(src));
        return;
    }

    hostidx = add_dest_by_addr(src, finfo, DEST_MUTE, -1, 0);
    if (!verify_client_fingerprint(finfo, keyblob, ntohs(clientkey->bloblen),
                                   hostidx)) {
        return;
    }
    memcpy(destlist[hostidx].encinfo->verifydata, verify,
            ntohs(clientkey->siglen));
    destlist[hostidx].encinfo->verifylen = ntohs(clientkey->siglen);
    glog2(finfo, "Received CLIENT_KEY from %s", destlist[hostidx].name);
}

/**
 * Process an expected CLIENT_KEY with closed group membership,
 * or with open group membership if REGISTER was received first.
 */
void handle_clientkey(const unsigned char *message, unsigned meslen,
                      struct finfo_t *finfo, const union sockaddr_u *su,
                      int hostidx)
{
    const struct client_key_h *clientkey;
    const unsigned char *keyblob, *verify;

    clientkey = (const struct client_key_h *)message;
    keyblob = (const unsigned char *)clientkey + sizeof(struct client_key_h);
    verify = keyblob + ntohs(clientkey->bloblen);

    if ((meslen < (clientkey->hlen * 4U)) ||
            ((clientkey->hlen * 4U) < sizeof(struct client_key_h) +
                ntohs(clientkey->bloblen) + ntohs(clientkey->siglen))) {
        glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                     "invalid message size", destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", su, destlist[hostidx].id,0,0);
        return;
    }
    if ((((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) &&
                (keyblob[0] != KEYBLOB_RSA)) ||
            ((keyextype == KEYEX_ECDH_ECDSA) &&
             (keyblob[0] != KEYBLOB_EC))) {
        glog1(finfo, "Rejecting CLIENT_KEY from %s: "
                     "invalid keyblob type", destlist[hostidx].name);
        return;
    }
    if (finfo->file_id != 0) {
        glog2(finfo, "Received CLIENT_KEY+ from %s", destlist[hostidx].name);
        return;
    }

    if (!verify_client_fingerprint(finfo, keyblob, ntohs(clientkey->bloblen),
                                   hostidx)) {
        return;
    }
    memcpy(destlist[hostidx].encinfo->verifydata, verify,
            ntohs(clientkey->siglen));
    destlist[hostidx].encinfo->verifylen = ntohs(clientkey->siglen);
    if (destlist[hostidx].registered) {
        if (!verify_client_key(finfo, hostidx)) {
            return;
        }
    }
    glog2(finfo, "Received CLIENT_KEY from %s", destlist[hostidx].name);
}

/**
 * Process an expected KEYINFO_ACK and validate the verify_data field.
 */
void handle_keyinfo_ack(const unsigned char *message, unsigned meslen,
                        struct finfo_t *finfo, const union sockaddr_u *su,
                        int hostidx)
{
    const struct keyinfoack_h *keyinfoack;
    unsigned char *verifydata, *verify_hash, *verify_test;
    int verifylen, len, dupmsg;
    unsigned int hashlen;

    keyinfoack = (const struct keyinfoack_h *)message;

    if ((meslen < (keyinfoack->hlen * 4U)) ||
            ((keyinfoack->hlen * 4U) < sizeof(struct keyinfoack_h))) {
        glog1(finfo, "Rejecting KEYINFO_ACK from %s: "
                     "invalid message size", destlist[hostidx].name);
        send_abort(finfo, "Invalid message size", su, destlist[hostidx].id,0,0);
        return;
    }

    if (keytype == KEY_NONE) {
        glog1(finfo, "Rejecting KEYINFO_ACK from %s: "
                     "encryption not enabled", destlist[hostidx].name);
        send_abort(finfo, "Encryption not enabled", su, destlist[hostidx].id,
                   0, 0);
        return;
    }

    if (!(verifydata = build_verify_data(finfo, hostidx, &verifylen))) {
        glog1(finfo, "Rejecting KEYINFO_ACK from %s: "
                     "error exporting client public key", destlist[hostidx].name);
        return;
    }
    verify_hash = safe_calloc(hmaclen, 1);
    verify_test = safe_calloc(VERIFY_LEN + hmaclen, 1);
    hash(hashtype, verifydata, verifylen, verify_hash, &hashlen);
    PRF(hashtype, VERIFY_LEN, groupmaster, sizeof(groupmaster),
            "client finished", verify_hash, hashlen, verify_test, &len);
    if (memcmp(keyinfoack->verify_data, verify_test, VERIFY_LEN)) {
        glog1(finfo, "Rejecting KEYINFO_ACK from %s: "
                     "verify data mismatch", destlist[hostidx].name);
        free(verifydata);
        free(verify_hash);
        free(verify_test);
        return;
    }

    free(verifydata);
    free(verify_hash);
    free(verify_test);

    dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
    glog2(finfo, "Received KEYINFO_ACK%s from %s", dupmsg ? "+" : "",
                 destlist[hostidx].name);
    destlist[hostidx].status = DEST_ACTIVE;
}

/**
 * Process an expected FILEINFO_ACK.
 */
void handle_fileinfo_ack(const unsigned char *message, unsigned meslen,
                         struct finfo_t *finfo, int hostidx)
{
    const struct fileinfoack_h *fileinfoack;
    struct timeval tv1, tv2;
    const uint32_t *addr;
    int clientcnt, dupmsg, isproxy, clientidx, i;

    fileinfoack = (const struct fileinfoack_h *)message;
    gettimeofday(&tv2, NULL);

    if ((meslen < (fileinfoack->hlen * 4U)) ||
            ((fileinfoack->hlen * 4U) < sizeof(struct fileinfoack_h))) {
        glog1(finfo, "Rejecting FILEINFO_ACK from %s: "
                     "invalid message size", destlist[hostidx].name);
        return;
    }
    clientcnt = (meslen - (fileinfoack->hlen * 4)) / 4;
    if ((clientcnt > 0) && (!destlist[hostidx].isproxy)) {
        glog1(finfo, "Rejecting FILEINFO_ACK from %s: "
                     "specified multiple clients but not a proxy",
                destlist[hostidx].name);
        return;
    }    

    if (ntohs(fileinfoack->file_id) != finfo->file_id) {
        glog1(finfo, "Rejecting FILEINFO_ACK from %s: "
                "invalid file ID %04X, expected %04X ", destlist[hostidx].name,
                ntohs(fileinfoack->file_id), finfo->file_id);
        return;
    }
    finfo->partial = finfo->partial &&
            ((fileinfoack->flags & FLAG_PARTIAL) != 0);

    tv1.tv_sec = ntohl(fileinfoack->tstamp_sec);
    tv1.tv_usec = ntohl(fileinfoack->tstamp_usec);
    destlist[hostidx].rtt = diff_usec(tv2, tv1) / 1000000.0;
    if (destlist[hostidx].rtt < CLIENT_RTT_MIN) {
        destlist[hostidx].rtt = CLIENT_RTT_MIN;
    }
    destlist[hostidx].rtt_measured = 1;
    destlist[hostidx].rtt_sent = 0;
    isproxy = destlist[hostidx].isproxy;
    dupmsg = (destlist[hostidx].status == DEST_ACTIVE);
    destlist[hostidx].status = DEST_ACTIVE;
    glog2(finfo, "Received FILEINFO_ACK%s from %s %s",
                 (dupmsg && !isproxy) ? "+" : "",
                 (isproxy) ? "proxy" : "client", destlist[hostidx].name);
    if (clientcnt > 0) {
        addr = (const uint32_t *)(message + (fileinfoack->hlen * 4));
        for (i = 0; i < clientcnt; i++) {
            dupmsg = 0;
            clientidx = find_client(addr[i]);
            if (clientidx == -1) {
                glog2(finfo, "Host %08X not in host list", ntohl(addr[i]));
                continue;
            } else {
                dupmsg = (destlist[clientidx].status == DEST_ACTIVE);
                destlist[clientidx].status = DEST_ACTIVE;
                destlist[clientidx].rtt = destlist[hostidx].rtt;
            }
            glog2(finfo, "  For client%s %s", dupmsg ? "+" : "",
                         destlist[clientidx].name);
        }
    }
    glog3(finfo, "send time = %d.%06d", tv1.tv_sec, tv1.tv_usec);
    glog3(finfo, "rx time = %d.%06d", tv2.tv_sec, tv2.tv_usec);
    glog3(finfo, "  rtt = %.6f", destlist[hostidx].rtt);

    return;
}
