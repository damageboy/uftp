#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WINDOWS

#include <winsock2.h>
#include <ws2tcpip.h>
#include "win_func.h"

#else

#include <unistd.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#endif

#include "uftp.h"
#include "uftp_common.h"
#include "encryption.h"

#define BLOCKSIZE 1500

SOCKET sock;
uint8_t groupmaster[MASTER_LEN];
uint8_t groupkey[MAXKEY], groupiv[MAXIV], hmackey[HMAC_LEN];
uint32_t myaddr;
int groupid, fileid, fsize, block_count, section_count;
int blocksize, payloadsize, encpayloadsize;
int hashtype, keytype, keylen, ivlen, hashlen;
RSA_key_t rsakey;
int phase, foundgroup;
int destcount;

uint8_t rand1[RAND_LEN];

struct destinfo_t {
  struct in_addr addr;
  uint8_t rand2[RAND_LEN];
  uint8_t premaster[MASTER_LEN];
  uint8_t premaster_enc[300];
  int premaster_enc_len;
  uint8_t master[MASTER_LEN];
  uint8_t key[MAXKEY];
  uint8_t iv[MAXIV];
  uint8_t hmac[HMAC_LEN];
  uint8_t verify[1000];
  int verifylen;
  int gotkeyinfo;
  int gotfileinfo;
} *destlist;

void send_register(struct sockaddr_in sin)
{
    unsigned char buf[BLOCKSIZE], seed[64], prf_buf[200];
    struct uftp_h *header;
    struct register_h *reg;
    unsigned char *reg_premaster;
    unsigned int explen;
    int prf_len, i;

    header = (struct uftp_h *)buf;
    reg = (struct register_h *)(buf + sizeof(struct uftp_h));
    reg_premaster = buf + sizeof(struct uftp_h) + sizeof(struct register_h);

    for (i=0;i<destcount;i++) {
        // send REGISTER
        memset(buf,0,sizeof(buf));
        header->uftp_id = UFTP_VER_NUM;
        header->func = REGISTER;
        header->blsize = htons(sizeof(struct register_h) + 
                destlist[i].premaster_enc_len);
        header->group_id = htonl(groupid);
        header->srcaddr = destlist[i].addr.s_addr;
        header->destaddr = sin.sin_addr.s_addr;
        reg->func = REGISTER;
        reg->destcount = 0;
        memcpy(reg->rand2,destlist[i].rand2,sizeof(destlist[i].rand2));
        memcpy(reg_premaster,
            destlist[i].premaster_enc,sizeof(destlist[i].premaster_enc));
        reg->premaster_len = htons(destlist[i].premaster_enc_len);
        if (sendto(sock, buf, sizeof(struct uftp_h) + ntohs(header->blsize),
                   0, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
            sockerror(0,0,"sendto failed for REGISTER");
            exit(1);
        }

        // calculate session keys
        memcpy(seed,rand1,sizeof(rand1));
        memcpy(seed+sizeof(rand1),
            destlist[i].rand2,sizeof(destlist[i].rand2));
        PRF(hashtype, MASTER_LEN,destlist[i].premaster,
                sizeof(destlist[i].premaster), "master secret",
                seed, sizeof(seed), prf_buf,&prf_len);
        memcpy(destlist[i].master,prf_buf, sizeof(destlist[i].master));
        //printhex("rand1",destlist[i].rand1,sizeof(destlist[i].rand1));
        //printhex("rand2",destlist[i].rand2,sizeof(destlist[i].rand2));
        //printhex("premaster",destlist[i].premaster,sizeof(destlist[i].premaster));
        //printhex("master",destlist[i].master,sizeof(destlist[i].master));

        explen = hashlen + keylen + ivlen;
        PRF(hashtype, explen, destlist[i].master, sizeof(destlist[i].master), 
            "key expansion", seed, sizeof(seed), prf_buf,&prf_len);
        memcpy(destlist[i].hmac, prf_buf, hashlen);
        memcpy(destlist[i].key, prf_buf + hashlen, keylen);
        memcpy(destlist[i].iv, prf_buf + hashlen + keylen, ivlen);
        //printhex("local hmac", destlist[i].hmac, hashlen);
        //printhex("local key", destlist[i].key, keylen);
        //printhex("local iv", destlist[i].iv, ivlen);
    }
}

void handle_announce(unsigned char *buf, struct sockaddr_in sin)
{
    struct uftp_h *header;
    struct announce_h *announce;
    unsigned char *keymod;
    uint32_t keyexp, n_groupid;
    uint16_t modlen;
    struct ip_mreq multi;
    int i;

    header = (struct uftp_h *)buf;
    announce = (struct announce_h *)(buf + sizeof(struct uftp_h));
    keymod = buf + sizeof(struct uftp_h) + sizeof(struct announce_h);

    fprintf(stderr,"Received ANNOUNCE from %s\n", inet_ntoa(sin.sin_addr));
    memcpy(rand1,announce->rand1,sizeof(announce->rand1));
    keyexp = ntohl(announce->keyexp);
    modlen = ntohs(announce->keylen);
    if (!import_RSA_key(&rsakey, keyexp, keymod, modlen)) {
        fprintf(stderr, "Failed to import public key");
        exit(0);
    }
    groupid = ntohl(header->group_id);
    keytype = announce->keytype;
    hashtype = announce->hashtype;
    get_key_info(keytype, &keylen, &ivlen);
    hashlen = get_hash_len(hashtype);
    payloadsize = ntohs(announce->mtu) - 28 - sizeof(struct uftp_h);
    encpayloadsize = payloadsize - sizeof(struct encrypted_h) - 16 - hashlen;
    blocksize = encpayloadsize - sizeof(struct fileseg_h);
    fprintf(stderr,"bsize=%d, epsize=%d, psize=%d\n",
            blocksize, encpayloadsize, payloadsize);

    multi.imr_multiaddr.s_addr=announce->privatemcast;
    multi.imr_interface.s_addr=htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
            (char *)&multi,sizeof(multi))==-1) {
        perror("Error joining multicast group");
        closesocket(sock);
        exit(1);
    }

    // Assume open group membership, and respond for all
    // Assume encryption enabled with HMAC signatures
    for (i=0;i<destcount;i++) {
        n_groupid = htonl(groupid);
        memcpy(destlist[i].verify, &n_groupid, sizeof(n_groupid));
        destlist[i].verifylen += sizeof(groupid);
        memcpy(destlist[i].verify + destlist[i].verifylen,
                &announce->privatemcast,
                sizeof(announce->privatemcast));
        destlist[i].verifylen += sizeof(announce->privatemcast);
        memcpy(destlist[i].verify + destlist[i].verifylen,rand1,sizeof(rand1));
        destlist[i].verifylen += sizeof(rand1);
        memcpy(destlist[i].verify + destlist[i].verifylen, destlist[i].rand2,
                sizeof(destlist[i].rand2));
        destlist[i].verifylen += sizeof(destlist[i].rand2);
        memcpy(destlist[i].verify + destlist[i].verifylen,destlist[i].premaster,
                sizeof(destlist[i].premaster));
        destlist[i].verifylen += sizeof(destlist[i].premaster);

        if (!RSA_encrypt(rsakey, destlist[i].premaster,
                sizeof(destlist[i].premaster), destlist[i].premaster_enc,
                &destlist[i].premaster_enc_len)) {
            fprintf(stderr, "couldn't encrypt");
            exit(1);
        }
    }
    foundgroup = 0;
    phase = KEYINFO;
    send_register(sin);
}

void send_infoack(struct sockaddr_in sin, int dest, int request)
{
    unsigned char buf[BLOCKSIZE], data[BLOCKSIZE];
    unsigned char iv[MAXIV], prf_buf[200], hmac[HMAC_LEN];
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    struct infoack_h *infoack;
    unsigned char *enc_sig, *enc_payload;
    int prf_len;
    unsigned int len;
    struct timeval tv;

    header = (struct uftp_h *)buf;
    encrypted=(struct encrypted_h *)(buf + sizeof(struct uftp_h));
    enc_sig=(unsigned char *)encrypted + sizeof(struct encrypted_h);
    enc_payload=enc_sig + hashlen;
    infoack = (struct infoack_h *)data;

    memset(buf, 0, sizeof(buf));
    memset(data, 0, sizeof(data));
    gettimeofday(&tv, NULL);
    infoack->func = INFO_ACK;
    infoack->destcount = 0;
    if (request == KEYINFO) {
        infoack->file_id = 0;
        hash(hashtype, destlist[dest].verify, destlist[dest].verifylen,
                hmac, &len);
        PRF(hashtype, VERIFY_LEN,groupmaster, sizeof(groupmaster), 
            "client finished", hmac, len, prf_buf, &prf_len);
        memcpy(infoack->verify_data,prf_buf,sizeof(infoack->verify_data));
    } else if (request == FILEINFO) {
        infoack->file_id = ntohs(fileid);
    } else {
        fprintf(stderr, "wrong request for INFO_ACK: %s\n",
                func_name(request));
        exit(1);
    }
    //printhex("encrypted INFO_ACK", infoack, sizeof(struct infoack_h));

    build_iv(iv, groupiv, ivlen, htonl(groupid),
             destlist[dest].addr.s_addr, htonl(tv.tv_sec), htonl(tv.tv_usec));
    if (!encrypt_block(keytype, iv, groupkey, data,
            sizeof(struct infoack_h), enc_payload, &len)) {
        fprintf(stderr, "encrypt failed for INFO_ACK");
        exit(1);
    }

    header->uftp_id = UFTP_VER_NUM;
    header->func = ENCRYPTED;
    header->blsize = htons(sizeof(struct encrypted_h) + hashlen + len);
    header->group_id = htonl(groupid);
    header->srcaddr = destlist[dest].addr.s_addr;
    header->destaddr = sin.sin_addr.s_addr;
    encrypted->tstamp_sec = htonl(tv.tv_sec);
    encrypted->tstamp_usec = htonl(tv.tv_usec);
    encrypted->sig_len = htons(hashlen);
    encrypted->payload_len = htons(len);

    create_hmac(hashtype, hmackey, hashlen, buf,
            sizeof(struct uftp_h) + ntohs(header->blsize), hmac, &len);
    if (len!=hashlen) {
        fprintf(stderr,"invalid hmac len: %d\n",len);
        exit(1);
    }
    memcpy(enc_sig, hmac, len);

    if (sendto(sock, buf, sizeof(struct uftp_h) + ntohs(header->blsize),
               0, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        sockerror(0,0,"sendto failed for INFO_ACK");
        exit(1);
    }
}

void handle_keyinfo(unsigned char *buf, struct sockaddr_in sin)
{
    unsigned char dec_groupmaster[MASTER_LEN], prf_buf[200], iv[MAXIV];
    struct uftp_h *header;
    struct keyinfo_h *keyinfo;
    struct destkey *dkey;
    int i, j, found;
    unsigned int len, explen;
    int prf_len, gotall;

    header = (struct uftp_h *)buf;
    keyinfo = (struct keyinfo_h *)(buf + sizeof(struct uftp_h));
    dkey = (struct destkey *)((char *)keyinfo + sizeof(struct keyinfo_h));

    fprintf(stderr,"Received KEYINFO from %s\n", inet_ntoa(sin.sin_addr));
    for (j=0;j<keyinfo->destcount;j++) {
        for (i=0,found=0;(i<destcount)&&(!found);i++) {
            if (dkey[j].destaddr==destlist[i].addr.s_addr) {
                found = 1;
            }
        }
        if (!found) {
            continue;
        }
        i--;
        //fprintf(stderr,"found name, id=%d\n",j);
        //printhex("encrypted group key",dkey[j].groupmaster,
        //         ntohs(keyinfo->groupmaster_len));

        /* decrypt group key */
        build_iv(iv, destlist[i].iv, ivlen, htonl(groupid), header->srcaddr,
                 keyinfo->tstamp_sec, keyinfo->tstamp_usec);
        if (!decrypt_block(keytype, iv, destlist[i].key, dkey[j].groupmaster,
                keyinfo->groupmaster_len, dec_groupmaster, &len)) {
            fprintf(stderr, "decrypt failed for group master");
            exit(1);
        }
        if (!foundgroup) {
            groupmaster[0]=header->uftp_id;
            memcpy(groupmaster+1,dec_groupmaster,len);
            printhex("group master",groupmaster, sizeof(groupmaster));

            foundgroup=1;
            explen = hashlen + keylen + ivlen;
            PRF(hashtype, explen, groupmaster, sizeof(groupmaster),
                    "key expansion", rand1, sizeof(rand1), prf_buf, &prf_len);
            memcpy(hmackey, prf_buf, hashlen);
            memcpy(groupkey, prf_buf + hashlen, keylen);
            memcpy(groupiv, prf_buf + hashlen + keylen, ivlen);
            printhex("hmackey",hmackey,hashlen);
            printhex("groupkey",groupkey,keylen);
            printhex("groupiv",groupiv,ivlen);
        } else {
            if (memcmp(groupmaster+1, dec_groupmaster, len)) {
                fprintf(stderr, "decrypted group master "
                                "doesn't match prior value");
                exit(1);
            }
        }
        if (!destlist[i].gotkeyinfo) {
            memcpy(destlist[i].verify+destlist[i].verifylen,
                groupmaster, sizeof(groupmaster));
            destlist[i].verifylen+=sizeof(groupmaster);
            destlist[i].gotkeyinfo=1;
        }
        send_infoack(sin, i, KEYINFO);
    }
    for (i=0,gotall=1;(i<destcount)&&gotall;i++) {
        gotall = gotall && (destlist[i].gotkeyinfo);
    }
    if (gotall) {
        phase = FILEINFO;
    }
}

void handle_fileinfo(unsigned char *buf, struct sockaddr_in sin)
{
    struct fileinfo_h *fileinfo;
    uint32_t *addrlist;
    int i, j, found, gotall;

    fileinfo = (struct fileinfo_h *)buf;
    addrlist = (uint32_t *)(buf + sizeof(struct fileinfo_h));

    fprintf(stderr,"Received FILEINFO from %s\n", inet_ntoa(sin.sin_addr));
    fileid = ntohs(fileinfo->file_id);
    // Assuming file is < 4GB
    fsize = ntohl(fileinfo->lofsize);
    block_count = ntohl(fileinfo->block_total);
    section_count = ntohs(fileinfo->section_total);

    for (j=0;j<ntohs(fileinfo->destcount);j++) {
        for (i=0,found=0;(i<destcount)&&(!found);i++) {
            if (addrlist[j]==destlist[i].addr.s_addr) {
                found = 1;
            }
        }
        if (!found) {
            continue;
        }
        i--;
        destlist[i].gotfileinfo = 1;
        send_infoack(sin, i, FILEINFO);
    }
    for (i=0,gotall=1;(i<destcount)&&gotall;i++) {
        gotall = gotall && (destlist[i].gotfileinfo);
    }
    if (gotall) {
        phase = FILESEG;
    }
}

void announce_phase()
{
    struct sockaddr_in sin;
    unsigned int addr_len;
    unsigned char buf[BLOCKSIZE],data[BLOCKSIZE];
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    unsigned char *enc_sig, *enc_payload;
    uint8_t hmacsav[HMAC_LEN], hmac[HMAC_LEN], iv[MAXIV];
    unsigned int recv_len, len;
    uint32_t baseaddr;
    char *func;
    int i;

    header = (struct uftp_h *)buf;

    // setup
    baseaddr = inet_addr("172.26.99.0");
    for (i=0;i<destcount;i++) {
        memset(&destlist[i],0,sizeof(destlist[i]));
        destlist[i].addr.s_addr = htonl(ntohl(baseaddr)+i);
        if (!get_random_bytes(destlist[i].rand2,sizeof(destlist[i].rand2))) {
            fprintf(stderr, "failed to generate rand2");
            exit(1);
        }
        if (!get_random_bytes(destlist[i].premaster,
                sizeof(destlist[i].premaster))) {
            fprintf(stderr, "failed to generate premaster");
            exit(1);
        }
    }
    memset(groupkey,0,sizeof(groupkey));
    memset(groupiv,0,sizeof(groupiv));
    memset(hmackey,0,sizeof(hmackey));

    phase = ANNOUNCE;
    do {
        memset(buf,0,sizeof(buf));
        addr_len=sizeof(sin);
        fprintf(stderr, "ready to receive...\n");
        if ((recv_len=recvfrom(sock,buf,sizeof(buf),0,
                (struct sockaddr *)&sin,&addr_len))==-1) {
            sockerror(0,0,"Error receiving");
            exit(1);
        }
        if (header->uftp_id!=UFTP_VER_NUM) {
            fprintf(stderr,"Invalid version number\n");
            exit(1);
        }
        if (recv_len<sizeof(struct uftp_h)+htons(header->blsize)) {
            fprintf(stderr,"Invalid packet size: %d\n", recv_len);
            exit(1);
        }

        if (header->func==ENCRYPTED) {
            encrypted=(struct encrypted_h *)(buf + sizeof(struct uftp_h));
            enc_sig=(unsigned char *)encrypted + sizeof(struct encrypted_h);
            enc_payload=enc_sig + hashlen;

            if (phase != FILEINFO) {
                fprintf(stderr, "not expecting encrypted message\n");
                exit(1);
            }
            // verify HMAC (assume sig is not RSA for now)
            memcpy(hmacsav,enc_sig,ntohs(encrypted->sig_len));
            memset(enc_sig, 0, ntohs(encrypted->sig_len));
            create_hmac(hashtype, hmackey, hashlen, buf, recv_len, hmac, &len);
            if (len!=hashlen) {
                fprintf(stderr,"invalid hmac len: %d\n",len);
                exit(1);
            }
            if (!memcmp(hmacsav,hmac,hashlen)) {
                fprintf(stderr,"hmac matches!\n");
            } else {
                fprintf(stderr,"hmac mismatch\n");
                printhex("calculated value",hmac,len);
                printhex("expected value",hmacsav,sizeof(hmacsav));
                exit(1);
            }

            // decrypt message
            build_iv(iv, groupiv, ivlen, htonl(groupid), header->srcaddr,
                     encrypted->tstamp_sec, encrypted->tstamp_usec);
            if (!decrypt_block(keytype, iv, groupkey, enc_payload,
                    ntohs(encrypted->payload_len), data, &len)) {
                fprintf(stderr, "decrypt failed\n");
                exit(1);
            }
            func = (char *)data;
            if (*func != FILEINFO) {
                fprintf(stderr, "Decrypted message not FILEINFO\n");
                exit(1);
            }
        } else {
            func = (char *)buf + sizeof(struct uftp_h);
        }
        switch (*func) {
        case ANNOUNCE:
            if (phase == ANNOUNCE) {
                handle_announce(buf, sin);
            }
            break; 
        case KEYINFO:
            if (phase == KEYINFO || phase == FILEINFO) {
                handle_keyinfo(buf, sin);
            }
            break;
        case FILEINFO:
            if (phase == FILEINFO) {
                handle_fileinfo(data, sin);
            }
            break;
        default:
            fprintf(stderr,"Invalid function: %d\n",header->func);
            exit(1);
        }
    } while (phase != FILESEG);
}

void send_status(struct sockaddr_in sin, int dest, int last_file_id,
                 int pass, int section, unsigned char *naks, int nak_count)
{
    unsigned char buf[BLOCKSIZE], data[BLOCKSIZE];
    unsigned char iv[MAXIV], hmac[HMAC_LEN];
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    struct status_h *status;
    unsigned char *enc_sig, *enc_payload, *naklist;
    unsigned int len, dlen;
    struct timeval tv;

    header = (struct uftp_h *)buf;
    encrypted=(struct encrypted_h *)(buf + sizeof(struct uftp_h));
    enc_sig=(unsigned char *)encrypted + sizeof(struct encrypted_h);
    enc_payload=enc_sig + hashlen;
    status = (struct status_h *)data;
    naklist = data + sizeof(struct status_h);

    memset(buf, 0, sizeof(buf));
    memset(data, 0, sizeof(data));
    gettimeofday(&tv, NULL);
    status->func = STATUS;
    status->file_id = ntohs(last_file_id);
    status->pass = pass;
    status->section = ntohs(section);
    status->nak_count = ntohl(nak_count);
    if (nak_count) {
        memcpy(naklist, naks, blocksize);
        dlen = sizeof(struct status_h) + blocksize;
    } else {
        dlen = sizeof(struct status_h);
    }

    build_iv(iv, groupiv, ivlen, htonl(groupid),
             destlist[dest].addr.s_addr, htonl(tv.tv_sec), htonl(tv.tv_usec));
    if (!encrypt_block(keytype, iv, groupkey, data, dlen, enc_payload, &len)) {
        fprintf(stderr, "encrypt failed for STATUS");
        exit(1);
    }

    header->uftp_id = UFTP_VER_NUM;
    header->func = ENCRYPTED;
    header->blsize = htons(sizeof(struct encrypted_h) + hashlen + len);
    header->group_id = htonl(groupid);
    header->srcaddr = destlist[dest].addr.s_addr;
    header->destaddr = sin.sin_addr.s_addr;
    encrypted->tstamp_sec = htonl(tv.tv_sec);
    encrypted->tstamp_usec = htonl(tv.tv_usec);
    encrypted->sig_len = htons(hashlen);
    encrypted->payload_len = htons(len);

    create_hmac(hashtype, hmackey, hashlen, buf,
            sizeof(struct uftp_h) + ntohs(header->blsize), hmac, &len);
    if (len!=hashlen) {
        fprintf(stderr,"invalid hmac len: %d\n",len);
        exit(1);
    }
    memcpy(enc_sig, hmac, len);

    if (sendto(sock, buf, sizeof(struct uftp_h) + ntohs(header->blsize),
               0, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        sockerror(0,0,"sendto failed for STATUS");
        exit(1);
    }
}

void send_complete(struct sockaddr_in sin, int dest, int last_file_id)
{
    unsigned char buf[BLOCKSIZE], data[BLOCKSIZE];
    unsigned char iv[MAXIV], hmac[HMAC_LEN];
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    struct complete_h *complete;
    unsigned char *enc_sig, *enc_payload;
    unsigned int len;
    struct timeval tv;

    header = (struct uftp_h *)buf;
    encrypted=(struct encrypted_h *)(buf + sizeof(struct uftp_h));
    enc_sig=(unsigned char *)encrypted + sizeof(struct encrypted_h);
    enc_payload=enc_sig + hashlen;
    complete = (struct complete_h *)data;

    memset(buf, 0, sizeof(buf));
    memset(data, 0, sizeof(data));
    gettimeofday(&tv, NULL);
    complete->func = COMPLETE;
    complete->file_id = ntohs(last_file_id);

    build_iv(iv, groupiv, ivlen, htonl(groupid),
             destlist[dest].addr.s_addr, htonl(tv.tv_sec), htonl(tv.tv_usec));
    if (!encrypt_block(keytype, iv, groupkey, data,
            sizeof(struct complete_h), enc_payload, &len)) {
        fprintf(stderr, "encrypt failed for COMPLETE");
        exit(1);
    }

    header->uftp_id = UFTP_VER_NUM;
    header->func = ENCRYPTED;
    header->blsize = htons(sizeof(struct encrypted_h) + hashlen + len);
    header->group_id = htonl(groupid);
    header->srcaddr = destlist[dest].addr.s_addr;
    header->destaddr = sin.sin_addr.s_addr;
    encrypted->tstamp_sec = htonl(tv.tv_sec);
    encrypted->tstamp_usec = htonl(tv.tv_usec);
    encrypted->sig_len = htons(hashlen);
    encrypted->payload_len = htons(len);

    create_hmac(hashtype, hmackey, hashlen, buf,
            sizeof(struct uftp_h) + ntohs(header->blsize), hmac, &len);
    if (len!=hashlen) {
        fprintf(stderr,"invalid hmac len: %d\n",len);
        exit(1);
    }
    memcpy(enc_sig, hmac, len);

    if (sendto(sock, buf, sizeof(struct uftp_h) + ntohs(header->blsize),
               0, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        sockerror(0,0,"sendto failed for COMPLETE");
        exit(1);
    }
}

void recv_data()
{
    uint8_t buf[BLOCKSIZE], hmac[HMAC_LEN], hmacsav[HMAC_LEN], data[BLOCKSIZE];
    struct uftp_h *header;
    struct encrypted_h *encrypted;
    struct fileseg_h *fileseg;
    struct done_h *done;
    struct doneconf_h *doneconf;
    unsigned char *enc_sig, *enc_payload;
    unsigned char *decdata, iv[MAXIV], naklist[BLOCKSIZE];
    int i, j, found, cnt, addr_len, recv_len;
    unsigned int hlen, decodelen;
    struct sockaddr_in sin;
    struct timeval t_start, t_end;
    double t_diff;
    char *naks, *func;
    uint32_t *addrlist; 
    int section_offset, blocks_this_sec, nakidx, naklistidx;

    header = (struct uftp_h *)buf;
    encrypted = (struct encrypted_h *)(buf + sizeof(struct uftp_h));
    enc_sig = (unsigned char *)encrypted + sizeof(struct encrypted_h);
    enc_payload = enc_sig + hashlen;

    func = (char *)data;
    fileseg = (struct fileseg_h *)data;
    done = (struct done_h *)data;
    doneconf = (struct doneconf_h *)data;
    decdata = data + sizeof (struct fileseg_h);

    naks = malloc(block_count);
    for (i=0;i<block_count;i++)
        naks[i] = 1;
    cnt=0;
    sleep(1);
    gettimeofday(&t_start,NULL);
    while (1) {
        memset(buf, 0, sizeof(buf));
        memset(data, 0, sizeof(data));
        addr_len=sizeof(sin);
        //fprintf(stderr,"receiving %d\n",cnt++);
        if ((recv_len=recvfrom(sock,buf,sizeof(buf),0,
                (struct sockaddr *)&sin,(unsigned int *)&addr_len))==-1) {
            sockerror(0,0,"Error receiving message");
            exit(1);
        }
        if (header->uftp_id!=UFTP_VER_NUM) {
            fprintf(stderr,"Invalid version number\n");
            exit(1);
        }
        if (recv_len!=sizeof(struct uftp_h)+htons(header->blsize)) {
            fprintf(stderr,"Invalid packet size: %d\n", recv_len);
            exit(1);
        }
        if (header->func!=ENCRYPTED) {
            fprintf(stderr,"Invalid function: %d\n",header->func);
            exit(1);
        }

        // verify HMAC (assume sig is not RSA for now)
        memcpy(hmacsav,enc_sig,ntohs(encrypted->sig_len));
        memset(enc_sig, 0, ntohs(encrypted->sig_len));
        create_hmac(hashtype, hmackey, hashlen, buf, recv_len, hmac, &hlen);
        if (hlen!=hashlen) {
            fprintf(stderr,"invalid hmac len: %d\n",hlen);
            exit(1);
        }
        if (memcmp(hmacsav,hmac,hashlen)) {
            fprintf(stderr,"hmac mismatch\n");
            printhex("calculated value",hmac,hlen);
            printhex("expected value",hmacsav,sizeof(hmacsav));
            exit(1);
        }

        /* decrypt pakcet */
        build_iv(iv, groupiv, ivlen, htonl(groupid), header->srcaddr,
                 encrypted->tstamp_sec, encrypted->tstamp_usec);
        if (!decrypt_block(keytype, iv, groupkey, enc_payload,
                ntohs(encrypted->payload_len), data, &decodelen)) {
            fprintf(stderr, "decrypt failed\n");
            exit(1);
        }

        if (*func == FILESEG) {
            int seq = ntohl(fileseg->seq_num);
            if (seq > block_count) {
                fprintf(stderr,"invalid seq_num: %d\n", seq);
            } else {
                naks[seq] = 0;
            }
        } else if (*func == DONE) {
            int pass, section, last_file_id;
            pass = done->pass;
            section = ntohs(done->section);
            last_file_id = ntohs(done->file_id);
            addrlist = (uint32_t *)((char *)done + sizeof(struct done_h));

            //////
            section_offset = (blocksize * 8) * (section - 1);
            blocks_this_sec = ((section < section_count) ?
                    (blocksize * 8) : (block_count % (blocksize * 8)));
            if (section_count && !blocks_this_sec) {
                blocks_this_sec = blocksize * 8;
            }

            memset(naklist, 0, sizeof(naklist));
            for (i = 0; i < blocks_this_sec; i++) {
                nakidx = i + section_offset;
                naklistidx = i;
                if (naks[nakidx]) {
                    log(0, 0, "NAK for %d", nakidx);
                    naklist[naklistidx >> 3] |= (1 << (naklistidx & 7));
                }
            }
            //////

            for (j=0;j<ntohs(done->destcount);j++) {
                for (i=0,found=0;(i<destcount)&&(!found);i++) {
                    if (addrlist[j]==destlist[i].addr.s_addr) {
                        found = 1;
                    }
                }
                if (!found) {
                    continue;
                }
                i--;
                if (pass==1 && last_file_id != 0) {
                    naklist[0] |= 0x01;
                    send_status(sin, i, last_file_id, pass, section,
                                naklist, 1);
                } else {
                    send_complete(sin, i, last_file_id);
                }
            }
        } else if (*func == DONE_CONF) {
            int count = 0;
            for (i=0;i<block_count;i++) {
                if (naks[i]) fprintf(stderr,"NAK for %d\n", i);
                count += naks[i];
            }
            fprintf(stderr,"total naks: %d\n",count);
            break;
        } else if (*func != FILEINFO) {
            handle_fileinfo(data, sin);
        }
    }
    gettimeofday(&t_end,NULL);
    t_diff = (double)((t_end.tv_usec-t_start.tv_usec)+1000000*(t_end.tv_sec-t_start.tv_sec))/1000000;
    fprintf(stderr,"received %d bytes in %.6f seconds\n",fsize,t_diff);
    fprintf(stderr,"throughput: %.2f KB/sec\n",fsize/t_diff/1024);
}


int main(int argc, char *argv[])
{
    struct sockaddr_in sin;
    struct ip_mreq multi;
    int buffer;

#ifdef WINDOWS
    struct WSAData data;

    if (WSAStartup(2, &data)) {
        fprintf(stderr, "Error in WSAStartup: %d\n", WSAGetLastError());
        exit(1);
    }
#endif
    applog=stderr;
    if (argc!=4) {
        fprintf(stderr,"usage: testclient multicast_interface multicast_ip count\n");
        exit(1);
    }
    myaddr = inet_addr(argv[1]);
    memset(&sin,0,sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(1044);
    if ((sock=socket(AF_INET,SOCK_DGRAM,0))==-1) {
        sockerror(0,0,"Error creating socket");
        exit(1);
    }
    buffer=2097152;
    if (setsockopt(sock,SOL_SOCKET,SO_RCVBUF,
            (char *)&buffer,sizeof(buffer))== -1) {
        sockerror(0,0,"Error setting receive buffer size");
        closesocket(sock);
        exit(1);
    }
    if (setsockopt(sock,SOL_SOCKET,SO_SNDBUF,
            (char *)&buffer,sizeof(buffer))== -1) {
        sockerror(0,0,"Error setting send buffer size");
        closesocket(sock);
        exit(1);
    }
    if (bind(sock,(struct sockaddr *)&sin,sizeof(sin))==-1) {
        sockerror(0,0,"Error binding socket");
        closesocket(sock);
        exit(1);
    }
    multi.imr_multiaddr.s_addr=inet_addr(argv[2]);
    multi.imr_interface.s_addr=htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
            (char *)&multi,sizeof(multi))==-1) {
        sockerror(0,0,"Error joining multicast group");
        closesocket(sock);
        exit(1);
    }
    destcount = atoi(argv[3]);
    if (destcount<1 || destcount>10000) {
        fprintf(stderr,"invalid destcount\n");
        exit(1);
    }
    destlist = calloc(destcount, sizeof(struct destinfo_t));
    crypto_init();
    announce_phase();
    recv_data();
    crypto_cleanup();
    free(destlist);
#ifdef WINDOWS
    WSACleanup();
#endif
    return 0;
}
