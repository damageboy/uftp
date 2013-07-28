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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include "win_func.h"

#else  // if WINDOWS

#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_common.h"
#include "server_transfer.h"

/**
 * Send out DONE_CONF messages specifiying all completed clients.
 * Returns 1 on success, 0 on fail
 */
int send_doneconf(const struct finfo_t *finfo, int attempt)
{
    unsigned char *buf;
    struct uftp_h *header;
    struct doneconf_h *doneconf;
    uint32_t *idlist;
    int rval;

    if (finfo->file_id != 0) {
        return 1;
    }

    buf = calloc(MAXMTU, 1); 
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    doneconf = (struct doneconf_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, DONE_CONF, finfo->group_id, finfo->group_inst,
                    grtt, destcount);
    doneconf->func = DONE_CONF;
    doneconf->hlen = sizeof(struct doneconf_h) / 4;

    idlist = (uint32_t *)((uint8_t *)doneconf + (doneconf->hlen * 4));
    rval = send_multiple(finfo, buf, DONE_CONF, attempt, idlist, DEST_DONE,
            (keytype != KEY_NONE), &receive_dest, 0);
    free(buf);
    return rval;
}

/**
 * Send out DONE messages specifiying active clients that haven't yet responded.
 * The grtt is being passed in because multiple threads could be touching it.
 * Returns 1 on success, 0 on fail
 */
int send_done(const struct finfo_t *finfo, int attempt, int section,
              double l_grtt)
{
    unsigned char *buf;
    struct uftp_h *header;
    struct done_h *done;
    uint32_t *idlist;
    int rval;

    buf = calloc(MAXMTU, 1); 
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    done = (struct done_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, DONE, finfo->group_id, finfo->group_inst,
                    l_grtt, destcount);
    done->func = DONE;
    done->hlen = sizeof(struct done_h) / 4;
    done->file_id = htons(finfo->file_id);
    done->section = htons(section);

    idlist = (uint32_t *)((uint8_t *)done + (done->hlen * 4));
    rval = send_multiple(finfo, buf, DONE, attempt, idlist, DEST_ACTIVE,
                         (keytype != KEY_NONE), &receive_dest, 0);
    free(buf);
    return rval;
}

/**
 * Creates the body of a CONG_CTRL message
 * This is done separate from sending the message so that the receiving thread
 * can perform this part.  We do this because the receiving thread checks
 * timeouts, and because the referenced data structures are now only
 * read/written in one thread, so we don't have to lock when we do this part. 
 */
void create_cc_list(unsigned char **body, int *len)
{
    struct cc_item *list;
    int *has_rtt, *no_rtt, has_rtt_len, no_rtt_len, maxlist, count, i;

    *body = calloc(blocksize, 1);
    if (*body == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    has_rtt = calloc(MAXDEST, sizeof(int));
    no_rtt = calloc(MAXDEST, sizeof(int));
    if ((has_rtt == NULL) || (no_rtt == NULL)) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }

    for (has_rtt_len = 0, no_rtt_len = 0, i = 0; i < destcount; i++) {
        if (i == clr) continue;
        if (destlist[i].rtt_sent) {
            has_rtt[has_rtt_len++] = i;
        } else {
            no_rtt[no_rtt_len++] = i;
        }
    }

    maxlist = blocksize / sizeof(struct cc_item);
    list = (struct cc_item *)*body;
    count = 0;
    if (clr != -1) {
        list[count].dest_id = destlist[clr].id;
        list[count].flags =
                FLAG_CC_CLR | FLAG_CC_RTT | (slowstart ? FLAG_CC_START : 0);
        list[count].rtt = quantize_grtt(destlist[clr].rtt);
        destlist[clr].rtt_sent = 1;
        count++;
    }
    for (i = 0; (i < no_rtt_len) && (*len < maxlist); i++) {
        list[count].dest_id = destlist[no_rtt[i]].id;
        list[count].flags = FLAG_CC_RTT | (slowstart ? FLAG_CC_START : 0);
        list[count].rtt = quantize_grtt(destlist[no_rtt[i]].rtt);
        count++;
        destlist[i].rtt_sent = 1;
    }
    for (i = 0; (i < has_rtt_len) && (*len < maxlist); i++) {
        list[count].dest_id = destlist[has_rtt[i]].id;
        list[count].flags = FLAG_CC_RTT | (slowstart ? FLAG_CC_START : 0);
        list[count].rtt = quantize_grtt(destlist[has_rtt[i]].rtt);
        count++;
        destlist[i].rtt_sent = 1;
    }
    *len = count * sizeof(struct cc_item);
    free(has_rtt);
    free(no_rtt);
}

/**
 * Send out a CONG_CTRL message
 */
void send_cong_ctrl(const struct finfo_t *finfo, double l_grtt,
                    uint16_t l_cc_seq, uint32_t l_cc_rate, 
                    unsigned char *body, int len)
{
    unsigned char *buf, *bodyptr, *encrypted, *outpacket;
    struct uftp_h *header;
    struct cong_ctrl_h *cong_ctrl;
    struct timeval now;
    int payloadlen, enclen;

    buf = calloc(MAXMTU, 1); 
    if (buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    header = (struct uftp_h *)buf;
    cong_ctrl = (struct cong_ctrl_h *)(buf + sizeof(struct uftp_h));

    set_uftp_header(header, CONG_CTRL, finfo->group_id, finfo->group_inst,
                    l_grtt, destcount);
    header->seq = htons(send_seq++);
    cong_ctrl->func = CONG_CTRL;
    cong_ctrl->hlen = sizeof(struct cong_ctrl_h) / 4;
    cong_ctrl->cc_seq = htons(l_cc_seq);
    cong_ctrl->cc_rate = htons(quantize_rate(l_cc_rate));
    gettimeofday(&now, NULL);
    cong_ctrl->tstamp_sec = htonl(now.tv_sec);
    cong_ctrl->tstamp_usec = htonl(now.tv_usec);

    bodyptr = (unsigned char *)cong_ctrl + (cong_ctrl->hlen * 4);
    memcpy(bodyptr, body, len);

    payloadlen = (cong_ctrl->hlen * 4) + len;
    if (keytype != KEY_NONE) {
        encrypted = NULL;
        if (!encrypt_and_sign(buf, &encrypted, payloadlen, &enclen, keytype,
                groupkey, groupsalt, &ivctr, ivlen, hashtype, grouphmackey,
                hmaclen, sigtype, keyextype, privkey, privkeylen)) {
            log0(0, 0, "Error encrypting CONG_CTRL");
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
                  (struct sockaddr *)&receive_dest,
                  family_len(receive_dest)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending CONG_CTRL");
    }
    log4(0, 0, "Sent CONG_CTRL, seq %d", l_cc_seq);
    free(buf);
    free(encrypted);
}

/**
 * Process an expected COMPLETE message
 */
void handle_complete(const unsigned char *message, unsigned meslen,
                     struct finfo_t *finfo, int hostidx)
{
    struct complete_h *complete;
    uint32_t *idlist;
    int clientcnt, clientidx, dupmsg, isproxy, i;
    char status[20];

    complete = (struct complete_h *)message;
    idlist = (uint32_t *)(message + (complete->hlen * 4));
    clientcnt = (meslen - (complete->hlen * 4)) / 4;

    if ((meslen < (complete->hlen * 4U)) || 
            ((complete->hlen * 4U) < sizeof(struct complete_h))) {
        log1(0, 0, "Rejecting COMPLETE from %s: invalid message size",
                    destlist[hostidx].name);
        return;
    }
    if (ntohs(complete->file_id) != finfo->file_id) {
        log1(0, 0, "Rejecting COMPLETE from %s: invalid file ID %04X, "
                   "expected %04X ", destlist[hostidx].name,
                   ntohs(complete->file_id), finfo->file_id);
        if (clientcnt > 0) {
            for (i = 0; i < clientcnt; i++) {
                clientidx = find_client(idlist[i]);
                if (clientidx == -1) {
                    log2(0, 0, "  For client %08X", ntohl(idlist[i]));
                } else {
                    log2(0, 0, "  For client %s", destlist[clientidx].name);
                }
            }
        }
        return;
    }

    dupmsg = (destlist[hostidx].status == DEST_DONE);
    isproxy = (destlist[hostidx].clientcnt != -1);
    destlist[hostidx].comp_status = complete->status;
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
    log2(0, 0, "Got COMPLETE%s%s from %s %s", status,
               (dupmsg && !isproxy) ? "+" : "",
               (isproxy) ? "proxy" : "client", destlist[hostidx].name);
    if (destlist[hostidx].clientcnt != -1) {
        for (i = 0; i < clientcnt; i++) {
            clientidx = find_client(idlist[i]);
            if (clientidx == -1) {
                log1(0, 0, "Client %08X via proxy %s not found",
                            ntohl(idlist[i]),
                            destlist[hostidx].name);
            } else if (destlist[clientidx].proxyidx != hostidx) {
                log1(0, 0, "Client %s found via proxy %s, expected proxy %s",
                            destlist[clientidx].name,
                            destlist[destlist[clientidx].proxyidx].name,
                            destlist[hostidx].name);
            } else {
                dupmsg = (destlist[clientidx].status == DEST_DONE);
                log2(0, 0, "  For client%s %s", dupmsg ? "+" : "",
                           destlist[clientidx].name);
                finfo->deststate[clientidx].conf_sent = 0;
                destlist[clientidx].status = DEST_DONE;
                destlist[clientidx].comp_status = complete->status;
                gettimeofday(&finfo->deststate[clientidx].time, NULL);
            }
        }
    } else {
        finfo->deststate[hostidx].conf_sent = 0;
        destlist[hostidx].status = DEST_DONE;
        gettimeofday(&finfo->deststate[hostidx].time, NULL);
    }
}

/**
 * Handle a EXT_TFMCC_ACK_INFO extension in a STATUS or CC_ACK
 * The mux_main mutex should already be locked
 */ 
void handle_tfmcc_ack_info(const struct tfmcc_ack_info_he *tfmcc, int hostidx)
{
    struct timeval now, msgtime;
    int flag_ss, flag_rtt, rate_1grtt;
    unsigned client_rate;
    double l_adv_grtt;

    gettimeofday(&now, NULL);
    msgtime.tv_sec = ntohl(tfmcc->tstamp_sec);
    msgtime.tv_usec = ntohl(tfmcc->tstamp_usec);
    destlist[hostidx].rtt = (double)(diff_usec(now, msgtime)) / 1000000;
    if (destlist[hostidx].rtt < CLIENT_RTT_MIN) {
        destlist[hostidx].rtt = CLIENT_RTT_MIN;
    }
    destlist[hostidx].rtt_measured = 1;
    destlist[hostidx].rtt_sent = 0;
    log4(0, 0, "  rtt = %.6f", destlist[hostidx].rtt);

    client_rate = unquantize_rate(ntohs(tfmcc->cc_rate));
    flag_ss = ((tfmcc->flags & FLAG_CC_START) != 0);
    flag_rtt = ((tfmcc->flags & FLAG_CC_RTT) != 0);

    // TODO: should we be checking the advertised GRTT instead of the real GRTT?
    if (destlist[hostidx].rtt > grtt) {
        grtt = destlist[hostidx].rtt;
    }
    if (!flag_ss) {
        slowstart = 0;
    }
    if (hostidx == clr) {
        log3(0, 0, "Got clr CC response for round %d", ntohs(tfmcc->cc_seq));
        rate_1grtt = (int)(datapacketsize / grtt);
        if (!flag_ss && !flag_rtt) {
            client_rate *= (int)(adv_grtt / destlist[hostidx].rtt);
        }
        if ((client_rate > (unsigned)rate + rate_1grtt) && !slowstart) {
            rate += rate_1grtt;
        } else {
            rate = client_rate;
        }
        packet_wait = (int32_t)(1000000.0 * datapacketsize / rate);
        last_clr_time = now;
    } else {
        log3(0, 0, "Got CC response for round %d", ntohs(tfmcc->cc_seq));
        if (client_rate < cc_rate) {
            cc_rate = (int)(client_rate * 0.9);
        }
        if (!flag_ss && !flag_rtt) {
            client_rate *= (int)(adv_grtt / destlist[hostidx].rtt);
        }
        if ((client_rate < (unsigned)rate) || (clr == -1)) {
            log3(0, 0, "Selected new clr %s", destlist[hostidx].name);
            if (!clr_drop) {
                rate = client_rate;
                packet_wait = (int32_t)(1000000.0 * datapacketsize / rate);
                rate_change = 1;
            } else if (client_rate < (unsigned)rate) {
                new_rate = client_rate;
            } else {
                new_rate = rate;
            }
            clr = hostidx;
            last_clr_time = now;
        }
    }
    l_adv_grtt = (double)datapacketsize / rate;
    if (l_adv_grtt < grtt) {
        l_adv_grtt = grtt;
    }
    if (l_adv_grtt > adv_grtt) {
        adv_grtt = l_adv_grtt;
    }
}

/**
 * Process an expected STATUS message
 * Sets *status_postion to the lowest numbered packet NAKed in this message
 */
void handle_status(const unsigned char *message, unsigned meslen,
                   struct finfo_t *finfo, int hostidx, int *status_position)
{
    struct status_h *status;
    struct tfmcc_ack_info_he *tfmcc;
    uint8_t *naklist, *he;
    unsigned section, current_section, naks, section_offset, blocks_this_sec;
    unsigned nakidx, listidx, i;
    unsigned extlen;

    status = (struct status_h *)message;
    naklist = ((uint8_t *)status) + (status->hlen * 4);
    section = ntohs(status->section);

    if ((meslen < (status->hlen * 4U)) || 
            ((status->hlen * 4U) < sizeof(struct status_h))) {
        log1(0, 0, "Rejecting STATUS from %s: invalid message size",
                    destlist[hostidx].name);
        return;
    }
    if (ntohs(status->file_id) != finfo->file_id) {
        log1(0, 0, "Rejecting STATUS from %s: invalid file ID %04X, "
                   "expected %04X ", destlist[hostidx].name,
                   ntohs(status->file_id), finfo->file_id );
        return;
    }

    tfmcc = NULL;
    if (status->hlen * 4U > sizeof(struct status_h)) {
        he = (uint8_t *)status + sizeof(struct status_h);
        if (*he == EXT_TFMCC_ACK_INFO) {
            tfmcc = (struct tfmcc_ack_info_he *)he;
            extlen = tfmcc->extlen * 4U;
            if ((extlen > (status->hlen * 4U) - sizeof(struct status_h)) ||
                    extlen < sizeof(struct tfmcc_ack_info_he)) {
                log1(0, 0, "Rejecting STATUS from %s: invalid extension size",
                           destlist[hostidx].name);
                return;
            }
        }
    }

    if (section >= finfo->big_sections) {
        section_offset = (finfo->big_sections * finfo->secsize_big) +
                ((section - finfo->big_sections) * finfo->secsize_small);
        blocks_this_sec = finfo->secsize_small;
    } else {
        section_offset = section * finfo->secsize_big;
        blocks_this_sec = finfo->secsize_big;
    }
    if (meslen < (status->hlen * 4U) + (blocks_this_sec / 8) + 1) {
        log1(0, 0, "Rejecting STATUS from %s: invalid message size",
                    destlist[hostidx].name);
        return;
    }

    if (mux_lock(mux_main)) {
        log0(0, 0, "Failed to lock mutex in handle_status");
        return;
    }
    if ((cc_type == CC_TFMCC) && tfmcc) {
        handle_tfmcc_ack_info(tfmcc, hostidx);
    }
    if (current_position < finfo->blocks) {
        if (current_position >= finfo->big_sections * finfo->secsize_big) {
            current_section = ((current_position -
                    (finfo->big_sections * finfo->secsize_big)) /
                    finfo->secsize_small) + finfo->big_sections;
        } else {
            current_section = current_position / finfo->secsize_big;
        }
        if (section >= current_section) {
            // Don't accept if it's at or ahead of the current transmit position
            log3(0, 0, "Dropping STATUS for section %d", section);
            if (mux_unlock(mux_main)) {
                log0(0, 0, "Failed to unlock mutex in handle_status");
            }
            return;
        }
    }

    for (*status_position = -1, naks = 0, i = 0; i < blocks_this_sec; i++) {
        // Each bit represents a NAK; check each one
        // Simplified: (naklist[listidx / 8] & (1 << (listidx % 8)))
        nakidx = i + section_offset;
        listidx = i;
        if ((naklist[listidx >> 3] & (1 << (listidx & 7))) != 0) {
            log4(0, 0, "Got NAK for %d", nakidx);
            finfo->naklist[nakidx] = 1;
            if (*status_position == -1) {
                *status_position = nakidx;
            }
            naks++;
        }
    }
    if (mux_unlock(mux_main)) {
        log0(0, 0, "Failed to unlock mutex in handle_status");
    }

    log2(0, 0, "Got %d NAKs for section %d from %s %s", naks, section,
            (destlist[hostidx].clientcnt != -1) ? "proxy" : "client",
            destlist[hostidx].name);
    log3(0, 0, "  status_position = %d", *status_position);
}

/**
 * Process an expected CC_ACK message
 */
void handle_cc_ack(const unsigned char *message, unsigned meslen,
                   struct finfo_t *finfo, int hostidx)
{
    struct cc_ack_h *cc_ack;
    struct tfmcc_ack_info_he *tfmcc;
    uint8_t *he;
    unsigned extlen;

    cc_ack = (struct cc_ack_h *)message;

    if ((meslen < (cc_ack->hlen * 4U)) || 
            ((cc_ack->hlen * 4U) < sizeof(struct cc_ack_h))) {
        log1(0, 0, "Rejecting CC_ACK from %s: invalid message size",
                    destlist[hostidx].name);
        return;
    }

    tfmcc = NULL;
    if (cc_ack->hlen * 4U > sizeof(struct cc_ack_h)) {
        he = (uint8_t *)cc_ack + sizeof(struct cc_ack_h);
        if (*he == EXT_TFMCC_ACK_INFO) {
            tfmcc = (struct tfmcc_ack_info_he *)he;
            extlen = tfmcc->extlen * 4U;
            if ((extlen > (cc_ack->hlen * 4U) - sizeof(struct cc_ack_h)) ||
                    extlen < sizeof(struct tfmcc_ack_info_he)) {
                log1(0, 0, "Rejecting CC_ACK from %s: invalid extension size",
                           destlist[hostidx].name);
                return;
            }
        }
    }

    log3(0, 0, "Got CC_ACK from %s", destlist[hostidx].name);
    if ((cc_type == CC_TFMCC) && tfmcc) {
        if (mux_lock(mux_main)) {
            log0(0, 0, "Failed to lock mutex in handle_cc_ack");
            return;
        }
        handle_tfmcc_ack_info(tfmcc, hostidx);
        if (mux_unlock(mux_main)) {
            log0(0, 0, "Failed to unlock mutex in handle_cc_ack");
            return;
        }
    }
}

/**
 * Sends out a data packet.  All headers should be populated
 */
int send_data(const struct finfo_t *finfo, unsigned char *packet, int datalen,
              unsigned char *encpacket)
{
    struct uftp_h *header;
    struct fileseg_h *fileseg;
    int payloadlen, enclen;
    unsigned char *outpacket;

    header = (struct uftp_h *)packet;
    fileseg = (struct fileseg_h *)(packet + sizeof(struct uftp_h));

    header->seq = htons(send_seq++);
    payloadlen = (fileseg->hlen * 4) + datalen;
    if (keytype != KEY_NONE) {
        if (!encrypt_and_sign(packet, &encpacket, payloadlen, &enclen, keytype,
                groupkey, groupsalt, &ivctr, ivlen, hashtype, grouphmackey,
                hmaclen, sigtype, keyextype, privkey, privkeylen)) {
            log0(0, 0, "Error encrypting FILESEG");
            return 0;
        }
        outpacket = encpacket;
        payloadlen = enclen;
    } else {
        outpacket = packet;
    }

    if (nb_sendto(sock, outpacket, payloadlen + sizeof(struct uftp_h), 0,
                  (struct sockaddr *)&receive_dest,
                  family_len(receive_dest)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error sending FILESEG");
        return 0;
    }

    return 1;
}

/**
 * Print the final statistics for the given file while in sync mode
 */
void print_sync_status(const struct finfo_t *finfo, struct timeval start_time)
{
    double elapsed_time, throughput;
    int i;

    if (finfo->file_id == 0) {
        log0(0, 0, "- Status -");
        log0(0, 0, "HSTATS;target;copy;overwrite;"
                   "skip;totalMB;time;speedKB/s");
        for (i = 0; i < destcount; i++) {
            if (destlist[i].clientcnt >= 0) {
                continue;
            }
            if (destlist[i].total_time > 0) {
                throughput = destlist[i].total_size /
                             destlist[i].total_time / 1024;
            } else {
                throughput = 0;
            }
            log0(0, 0, "STATS;%s;%d;%d;%d;%sMB;%.3f;%.2fKB/s",
                    destlist[i].name, destlist[i].num_copy,
                    destlist[i].num_overwrite, destlist[i].num_skip,
                    printll(destlist[i].total_size / 1048576),
                    destlist[i].total_time,
                    throughput);
        }
        return;
    }

    for (i = 0; i < destcount; i++) {
        if (destlist[i].clientcnt >= 0) {
            continue;
        }
        clog0(0, 0, "RESULT;%s;%s;%sKB;", destlist[i].name,
                finfo->destfname, printll(finfo->size / 1024));
        switch (destlist[i].status) {
        case DEST_MUTE:
            slog0("mute;");
            break;
        case DEST_LOST:
            slog0("lost;");
            break;
        case DEST_ABORT:
            slog0("aborted;");
            break;
        case DEST_DONE:
            if (sync_preview) {
                throughput = rate / 8;
                elapsed_time = finfo->size / (throughput * 1024);
            } else {
                elapsed_time = (double)diff_usec(finfo->deststate[i].time,
                                                 start_time) / 1000000;
                if (elapsed_time > 0) {
                    throughput = finfo->size / elapsed_time / 1024;
                } else {
                    throughput = 0;
                }
            }
            switch (destlist[i].comp_status) {
            case COMP_STAT_NORMAL:
                slog0("copy;%.2fKB/s", throughput);
                destlist[i].num_copy++;
                destlist[i].total_time += elapsed_time;
                destlist[i].total_size += finfo->size;
                break;
            case COMP_STAT_SKIPPED:
                slog0("skipped;");
                destlist[i].num_skip++;
                break;
            case COMP_STAT_OVERWRITE:
                slog0("overwritten;%.2fKB/s", throughput);
                destlist[i].num_overwrite++;
                destlist[i].total_time += elapsed_time;
                destlist[i].total_size += finfo->size;
                break;
            case COMP_STAT_REJECTED:
                slog0("rejected;");
                break;
            default:
                slog0("Unknown;");
                break;
            }
            break;
        default:
            slog0("Unknown;");
            break;
        }
    }
}

/**
 * Print the final statistics for the given file
 */
void print_status(const struct finfo_t *finfo, struct timeval start_time)
{
    struct timeval done_time;
    double elapsed_time;
    int i;

    if (sync_mode) {
        print_sync_status(finfo, start_time);
        return;
    }

    if (finfo->file_id == 0) {
        log0(0, 0, "Group complete");
        return;
    }

    log0(0, 0, "Transfer status:");
    for (done_time = start_time, i = 0; i < destcount; i++) {
        if (destlist[i].clientcnt >= 0) {
            continue;
        }
        clog0(0, 0, "Host: %-15s  Status: ", destlist[i].name);
        switch (destlist[i].status) {
        case DEST_MUTE:
            slog0("Mute");
            break;
        case DEST_LOST:
            slog0("Lost connection");
            break;
        case DEST_ABORT:
            slog0("Aborted");
            break;
        case DEST_DONE:
            if (destlist[i].comp_status == COMP_STAT_REJECTED) {
                slog0("Rejected");
                break;
            }
            if (diff_usec(finfo->deststate[i].time, done_time) > 0) {
                done_time = finfo->deststate[i].time;
            }
            elapsed_time = (double)diff_usec(finfo->deststate[i].time,
                                             start_time) / 1000000;
            slog0("Completed   time: %7.3f seconds", elapsed_time);
            break;
        default:
            slog0("Unknown  code: %d", destlist[i].status);
            break;
        }
    }
    elapsed_time = (double)diff_usec(done_time, start_time) / 1000000;
    log1(0, 0, "Total elapsed time: %.3f seconds", elapsed_time);
    log1(0, 0, "Overall throughput: %.2f KB/s",
               (elapsed_time != 0) ? (finfo->size / elapsed_time / 1024) : 0);
}

