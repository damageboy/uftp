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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <math.h>

#ifdef WINDOWS

#include <io.h>
#include "win_func.h"

#else  // if WINDOWS

#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_config.h"
#include "server_common.h"
#include "server_announce.h"
#include "server_transfer.h"

/**
 * Check an announce phase message and pass to appropriate message handler,
 * decrypting first if necessary
 * Returns 1 on success, 0 on error
 */
int handle_announce_phase(unsigned char *packet, unsigned char *decrypted,
                          int packetlen, const union sockaddr_u *receiver,
                          struct finfo_t *finfo,
                          int announce, int open_group, int regconf)
{
    struct uftp_h *header;
    unsigned char *message;
    int hostidx;
    unsigned decryptlen, meslen;
    uint8_t *func;

    header = (struct uftp_h *)packet;
    hostidx = find_client(header->src_id);
    if ((keytype != KEY_NONE) && (header->func == ENCRYPTED)) {
        if (hostidx == -1) {
            glog2(finfo, "Got encrypted packet from unknown receiver %08X",
                         ntohl(header->src_id));
            return 0;
        }
        if (!validate_and_decrypt(packet, packetlen, &decrypted, &decryptlen,
                keytype, groupkey, groupsalt, ivlen, hashtype, grouphmackey,
                hmaclen, sigtype, keyextype, destlist[hostidx].encinfo->pubkey,
                destlist[hostidx].encinfo->pubkeylen)) {
            glog1(finfo, "Rejecting message from %s: decrypt/validate failed",
                         destlist[hostidx].name);
            return 0;
        }
        func = (uint8_t *)decrypted;
        message = decrypted;
        meslen = decryptlen;
    } else {
        if ((keytype != KEY_NONE) && ((header->func == KEYINFO_ACK) ||
                                      (header->func == FILEINFO_ACK))) {
            glog1(finfo, "Rejecting %s message from %08X: not encrypted",
                         func_name(header->func), ntohl(header->src_id));
            return 0;
        }
        func = (uint8_t *)&header->func;
        message = packet + sizeof(struct uftp_h);
        meslen = packetlen - sizeof(struct uftp_h);
    }

    if (*func == ABORT) {
        handle_abort(message, meslen, hostidx, finfo, header->src_id);
        return 1;
    }

    if (hostidx == -1) {
        if (open_group) {
            if (*func == REGISTER) {
                handle_open_register(message, meslen, finfo, receiver,
                                     header->src_id, regconf);
            } else if (*func == CLIENT_KEY) {
                handle_open_clientkey(message, meslen, finfo, receiver,
                                      header->src_id);
            } else {
                glog1(finfo, "Invalid function: expected "
                             "REGISTER or CLIENT_KEY, got %s",func_name(*func));
            }
        } else {
            glog1(finfo, "Host %08X not in host list", ntohl(header->src_id));
            send_abort(finfo, "Not in host list", receiver, header->src_id,0,0);
        }
    } else {
        switch (destlist[hostidx].status) {
        case DEST_MUTE:
            if (*func == REGISTER) {
                handle_register(message, meslen, finfo, receiver,
                                hostidx, regconf, open_group);
            } else if (*func == CLIENT_KEY) {
                handle_clientkey(message, meslen, finfo, receiver, hostidx);
            } else {
                glog1(finfo, "Invalid function: expected "
                             "REGISTER or CLIENT_KEY, got %s",func_name(*func));
            }
            break;
        case DEST_REGISTERED:
            if (announce && (*func == KEYINFO_ACK)) {
                handle_keyinfo_ack(message, meslen, finfo, receiver, hostidx);
            } else if (!announce && (*func == FILEINFO_ACK)) {
                handle_fileinfo_ack(message, meslen, finfo, hostidx);
            } else if (*func == REGISTER) {
                handle_register(message, meslen, finfo, receiver,
                                hostidx, regconf, open_group);
            } else if (*func == CLIENT_KEY) {
                glog2(finfo, "Received CLIENT_KEY+ from %s",
                             destlist[hostidx].name);
            } else if (!announce && (*func == COMPLETE)) {
                handle_complete(message, meslen, finfo, hostidx);
            } else {
                glog1(finfo, "Received invalid message %s from %s",
                             func_name(*func), destlist[hostidx].name);
            }
            break;
        case DEST_ACTIVE:
            if (*func == REGISTER) {
                handle_register(message, meslen, finfo, receiver,
                                hostidx, regconf, open_group);
            } else if (*func == CLIENT_KEY) {
                glog2(finfo, "Received CLIENT_KEY+ from %s",
                             destlist[hostidx].name);
            } else if (announce && (*func == KEYINFO_ACK)) {
                finfo->deststate[hostidx].conf_sent = 0;
                handle_keyinfo_ack(message, meslen, finfo, receiver, hostidx);
            } else if (!announce && (*func == FILEINFO_ACK)) {
                handle_fileinfo_ack(message, meslen, finfo, hostidx);
            } else if (!announce && (*func == COMPLETE)) {
                handle_complete(message, meslen, finfo, hostidx);
            } else {
                glog1(finfo, "Received invalid message %s from %s",
                             func_name(*func), destlist[hostidx].name);
            }
            break;
        default:
            glog1(finfo, "Received invalid message %s from %s",
                         func_name(*func), destlist[hostidx].name);
            break;
        }
    }

    return 1;
}

/**
 * Perform the Announce/Register phase for a particular group/file
 * Group & encryption: ->ANNOUNCE <-REGISTER ->KEYINFO <-KEYINFO_ACK
 * Group & no encryption: ->ANNOUNCE <-REGISTER ->REG_CONF
 * Files within a group: ->FILEINFO <-FILEINFO_ACK
 * If client_key == 1, REGISTER is followed by CLIENT_KEY
 * Returns ERR_NONE if at least one client responsed,
 * or either ERR_ANNOUNCE or ERR_FILEINFO if none responded
 */
int announce_phase(struct finfo_t *finfo)
{
    int attempt, resend, announce, regconf, keyinfo, fileinfo;
    int open_group, anyerror;
    int len, rval, rcv_status, last_pass, gotall, gotone, allreg, regdone, i;
    unsigned char *packet, *decrypted;
    struct timeval timeout, next_send, now;
    union sockaddr_u receiver;
    int grtt_set;
    uint8_t tos;

    if (finfo->file_id) {
        glog2(finfo, "File ID: %04X  Name: %s", finfo->file_id,finfo->filename);
        glog2(finfo, "  sending as: %s", finfo->destfname);
        switch (finfo->ftype) {
        case FTYPE_REG:
            glog2(finfo, "Bytes: %s  Blocks: %d  Sections: %d", 
                        printll(finfo->size), finfo->blocks, finfo->sections);
            glog3(finfo, "small section size: %d, "
                "big section size: %d, " "# big sections: %d",
                finfo->secsize_small, finfo->secsize_big, finfo->big_sections);
            break;
        case FTYPE_DIR:
            glog2(finfo, "Empty directory");
            break;
        case FTYPE_LINK:
            glog2(finfo, "Symbolic link to %s", finfo->linkname);
            break;
        case FTYPE_DELETE:
            glog2(finfo, "Delete file/directory with this name");
            break;
        case FTYPE_FREESPACE:
            glog2(finfo, "Free disk space query");
            break;
        }
    } else {
        glog2(finfo, "Initializing group");
    }

    rval = ERR_NONE;
    packet = safe_calloc(MAXMTU, 1);
    decrypted = safe_calloc(MAXMTU, 1);
    announce = (finfo->file_id == 0);
    regconf = (announce && (keytype == KEY_NONE));
    keyinfo = (announce && (keytype != KEY_NONE));
    fileinfo = (finfo->file_id != 0);
    open_group = (destcount == 0);
    for (i = 0; i < destcount; i++) {
        // At start of group, initialize all clients/proxies to DEST_MUTE.
        // At start of file, initialize proxies to DEST_ACTIVE (since they
        // don't respond directly to a FILEINFO) and clients to DEST_REGISTERED.
        if (announce) {
            destlist[i].status = DEST_MUTE;
        } else if (!client_error(i)) {
            if (destlist[i].isproxy) {
                destlist[i].status = DEST_ACTIVE;
            } else {
                destlist[i].status = DEST_REGISTERED;
            }
            destlist[i].freespace = -1;
        }
    }

    gettimeofday(&next_send, NULL);
    add_timeval_d(&next_send, 3 * grtt);
    resend = 1;
    attempt = 1;
    last_pass = 0;
    regdone = 0;
    grtt_set = !announce;
    while (attempt <= robust) {
        if (user_abort) break;
        // On the initial pass, or when the timeout trips,
        // send any necessary messages.
        if (resend) {
            if (keyinfo && !send_keyinfo(finfo, attempt)) {
                continue;
            }
            if (announce && !send_regconf(finfo, attempt, regconf)) {
                continue;
            }
            if (fileinfo && !send_fileinfo(finfo, attempt)) {
                continue;
            }
            if (announce && !send_announce(finfo, attempt, open_group)) {
                continue;
            }
            resend = 0;
        }
        gettimeofday(&now, NULL);
        if (cmptimestamp(now, next_send) >= 0) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } else {
            timeout = diff_timeval(next_send, now);
        }
        if ((rcv_status = read_packet(sock, &receiver, packet, &len,
                                      MAXMTU, &timeout, &tos)) == -1) {
            continue;
        } else if (rcv_status == 0) {
            attempt++;
            grtt_set |= recalculate_grtt(finfo, grtt_set, 0);
            gettimeofday(&next_send, NULL);
            add_timeval_d(&next_send, 3 * grtt);
            resend = 1;
            if (last_pass) break;
            continue;
        }
        if (!validate_packet(packet, len, finfo)) {
            continue;
        }

        if (!handle_announce_phase(packet, decrypted, len, &receiver, finfo,
                                   announce, open_group, regconf)) {
            continue;
        }
        if (!open_group) {
            for (i = 0, gotall = 1, allreg = 1;
                    (i < destcount) && (gotall || allreg); i++) {
                if (announce) {
                    gotall = gotall && ((destlist[i].status == DEST_ACTIVE) ||
                                        (destlist[i].status == DEST_ABORT));
                    allreg = allreg && ((destlist[i].status == DEST_ACTIVE) ||
                                (destlist[i].status == DEST_REGISTERED) ||
                                (destlist[i].status == DEST_ABORT));
                } else {
                    gotall = gotall && ((destlist[i].status == DEST_ACTIVE) ||
                                        (destlist[i].status == DEST_DONE) ||
                                        (client_error(i)));
                }
            }
            if (gotall) {
                // Break out right away if this is a file registration.
                // For group registration, do one last wait, even if 
                // encryption is enabled since we can still send a
                // REG_CONF for a client behind a proxy.
                // Change the timeout to 1 * grtt
                // to allow for late registers.
                if (finfo->file_id != 0) break;
                recalculate_grtt(finfo, grtt_set, 0);
                gettimeofday(&next_send, NULL);
                add_timeval_d(&next_send, grtt);
                if (!last_pass) {
                    glog2(finfo, "Late registers:");
                }
                last_pass = 1;
                send_regconf(finfo, attempt + 1, regconf);
            } else if (announce && allreg && !regdone) {
                // All have registered, so don't wait to send the next message
                resend = 1;
                regdone = 1;
            }
        }
    }
    recalculate_grtt(finfo, 1, 1);
    for (i = 0, gotone = 0, anyerror = 0; i < destcount; i++) {
        gotone = gotone || (((destlist[i].status == DEST_ACTIVE) || 
                             (destlist[i].status == DEST_DONE)) && 
                            (!destlist[i].isproxy));
        if (destlist[i].status == DEST_REGISTERED) {
            if (announce) {
                glog1(finfo, "Couldn't get KEYINFO_ACK from %s",
                             destlist[i].name);
            } else {
                glog1(finfo, "Couldn't get FILEINFO_ACK from %s",
                             destlist[i].name);
            }
            destlist[i].status = DEST_LOST;
            anyerror = 1;
        }
        if ((destlist[i].status == DEST_MUTE) ||
                (destlist[i].status == DEST_ABORT)) {
            anyerror = 1;
        }
    }
    if (anyerror && quit_on_error) {
        glog0(finfo, "Aboring all clients");
        send_abort(finfo, "A client dropped out, aborting all",
                &receive_dest, 0, (keytype != KEY_NONE), 0);
        for (i = 0; i < destcount; i++) {
            if (destlist[i].status == DEST_ACTIVE) {
                destlist[i].status = DEST_ABORT;
            }
        }
        rval = (announce ? ERR_NO_REGISTER : ERR_NO_FILEINFO);
    }
    if (!gotone) {
        glog0(finfo, "Announce timed out");
        rval = (announce ? ERR_NO_REGISTER : ERR_NO_FILEINFO);
    }
    if (open_group) {
        send_regconf(finfo, attempt, regconf);
    }
    if ((finfo->file_id == 0) && status_file) {
        for (i = 0; i < destcount; i++) {
            if (destlist[i].status == DEST_ACTIVE) {
                fprintf(status_file, "CONNECT;success;%s\n", destlist[i].name);
            } else {
                fprintf(status_file, "CONNECT;failed;%s\n", destlist[i].name);
            }
        }
    }
    free(packet);
    free(decrypted);
    return rval;
}

/**
 * Check a transfer phase message and pass to appropriate message handler,
 * decrypting first if necessary
 */
void handle_transfer_phase(unsigned char *packet,unsigned char *decrypted,
                           int packetlen, const union sockaddr_u *receiver,
                           struct finfo_t *finfo, int *got_naks)
{
    struct uftp_h *header;
    unsigned char *message;
    int hostidx;
    unsigned int decryptlen, meslen;
    uint8_t *func;

    header = (struct uftp_h *)packet;
    hostidx = find_client(header->src_id);
    if ((keytype != KEY_NONE) && (header->func == ENCRYPTED)) {
        if (hostidx == -1) {
            glog1(finfo, "Host %08X not in host list", ntohl(header->src_id));
            send_abort(finfo, "Not in host list", receiver, header->src_id,0,0);
            return;
        }
        if (!validate_and_decrypt(packet, packetlen, &decrypted, &decryptlen,
                keytype, groupkey, groupsalt, ivlen, hashtype, grouphmackey,
                hmaclen, sigtype, keyextype, destlist[hostidx].encinfo->pubkey,
                destlist[hostidx].encinfo->pubkeylen)) {
            glog1(finfo, "Rejecting message from %s: decrypt/validate failed",
                         destlist[hostidx].name);
            return;
        }
        func = (uint8_t *)decrypted;
        message = decrypted;
        meslen = decryptlen;
    } else {
        if ((keytype != KEY_NONE) && ( (header->func == STATUS) ||
                (header->func == COMPLETE) || (header->func == ABORT))) {
            glog1(finfo, "Rejecting %s message from %08X: not encrypted",
                         func_name(header->func), ntohl(header->src_id));
            return;
        }
        func = (uint8_t *)&header->func;
        message = packet + sizeof(struct uftp_h);
        meslen = packetlen - sizeof(struct uftp_h);
    }

    if (*func == ABORT) {
        handle_abort(message, meslen, hostidx, finfo, header->src_id);
    } else if (hostidx == -1) {
        glog1(finfo, "Host %08X not in host list", ntohl(header->src_id));
        send_abort(finfo, "Not in host list", receiver, header->src_id, 0, 0);
    } else {
        switch (destlist[hostidx].status) {
        case DEST_ACTIVE:
        case DEST_ACTIVE_NAK:
            if (*func == STATUS) {
                handle_status(message, meslen, finfo, hostidx, got_naks);
            } else if (*func == COMPLETE) {
                handle_complete(message, meslen, finfo, hostidx);
            } else if (*func == CC_ACK) {
                handle_cc_ack(message, meslen, finfo, hostidx);
            } else {
                glog1(finfo, "Received invalid message %s from %s",
                             func_name(*func), destlist[hostidx].name);
            }
            break;
        case DEST_DONE:
            if (*func == COMPLETE) {
                handle_complete(message, meslen, finfo, hostidx);
            } else {
                glog1(finfo, "Received invalid message %s from %s",
                            func_name(*func), destlist[hostidx].name);
            }
            break;
        }
    }
    return;
}

/**
 * Seeks to a particular block in a file
 * Returns 1 on success, 0 on error
 */
int seek_block(const struct finfo_t *finfo, int file, int block,
               f_offset_t *offset)
{
    f_offset_t new_offset;

    if ((new_offset = lseek_func(file, 
            ((f_offset_t)block * blocksize) - *offset, SEEK_CUR)) == -1) {
        gsyserror(finfo, "lseek failed for file");
        return 0;
    }
    if (new_offset != (f_offset_t)block * blocksize) {
        glog0(finfo, "block %d: offset is %s", block, printll(new_offset));
        glog0(finfo, "  should be %s", printll((f_offset_t)block * blocksize));
        if ((new_offset = lseek_func(file, ((f_offset_t)block * blocksize),
                                     SEEK_SET)) == -1) {
            gsyserror(finfo, "lseek failed for file");
            return 0;
        }
    }
    *offset = new_offset;
    return 1;
}

/*
    TODO: Have the server echo back any received NAKs, and have the
    clients suppress their own NAKs based on that.

*/

/**
 * Variables shared between the sending and receiving threads
 */
mux_t mux_main;

struct cc_queue_item {
    unsigned char *data;
    int len;
};

#define CC_QUEUE_LEN 100
static struct cc_queue_item cc_queue[CC_QUEUE_LEN];
static int cc_queue_start, cc_queue_end, end_of_pass;

static int file_done_flag, rewind_flag, rewind_pending_flag, max_time_timeout;

int rate_change;
uint32_t current_position;
uint16_t cc_seq;
uint32_t cc_rate;
double adv_grtt;

// TODO: not shared between threads, move?
int slowstart, clr, clr_drop, new_rate;
struct timeval last_clr_time;

static int file;

/**
 * Read item from cc_queue.  The calling thread must be holding the lock.
 * Returns the head of the list, or NULL if the list is empty.
 */
void get_cc_queue(unsigned char **item, int *len)
{
    if ((cc_queue_start == cc_queue_end) &&
            (cc_queue[cc_queue_end].data == NULL)) {
        *item = NULL;
        *len = 0;
        return;
    }

    *item = cc_queue[cc_queue_start].data;
    *len = cc_queue[cc_queue_start].len;
    cc_queue[cc_queue_start].data = NULL;
    cc_queue[cc_queue_start++].len = 0;
    if (cc_queue_start == CC_QUEUE_LEN) {
        cc_queue_start = 0;
    }
}

/**
 * Put item on cc_queue.  The calling thread must be holding the lock.
 * Returns true if the item was added, false if the list is full.
 */
int put_cc_queue(const struct finfo_t *finfo, unsigned char *item, int len)
{
    if ((cc_queue_start == cc_queue_end) &&
            (cc_queue[cc_queue_end].data != NULL)) {
        glog1(finfo, "cc_queue full");
        return 0;
    }
    
    cc_queue[cc_queue_end].data = item;
    cc_queue[cc_queue_end++].len = len;
    if (cc_queue_end == CC_QUEUE_LEN) {
        cc_queue_end = 0;
    }
    return 1;
}

/**
 * Thread for sending all packets during the transfer phase
 */
THREAD_FUNC transfer_send_thread(void *infop)
{
    unsigned char *packet, *encpacket, *data, *cc_body;
    struct uftp_h *header;
    struct fileseg_h *fileseg;
    struct tfmcc_data_info_he *tfmcc;
    int numbytes, attempt, l_file_done_flag, current_nak, cc_len, done_sent;
    double l_adv_grtt;
    uint16_t l_cc_seq, pass, section, last_section;
    uint32_t l_cc_rate, block;
    int l_packet_wait, l_rate_change, max_time;
    struct timeval last_sent, current_sent, now, start_time;
    int64_t overage, tdiff;
    f_offset_t offset, curr_offset;
    struct finfo_t *finfo;

    finfo = infop;
    // Not mutexed, but should be OK when the thread first starts
    l_cc_seq = cc_seq;
    l_cc_rate = cc_rate;
    l_packet_wait = packet_wait;
    l_adv_grtt = adv_grtt;
    l_rate_change = 0;

    packet = safe_calloc(MAXMTU, 1);
    encpacket = safe_calloc(MAXMTU, 1);
    header = (struct uftp_h *)packet;
    fileseg = (struct fileseg_h *)(packet + sizeof(struct uftp_h));
    if (cc_type == CC_TFMCC) {
        tfmcc = (struct tfmcc_data_info_he *)((unsigned char *)fileseg +
                sizeof(struct fileseg_h));
        tfmcc->exttype = EXT_TFMCC_DATA_INFO;
        tfmcc->extlen = sizeof(struct tfmcc_data_info_he) / 4;
        fileseg->hlen = (sizeof(struct fileseg_h) +
                            sizeof(struct tfmcc_data_info_he)) / 4;
    } else {
        tfmcc = NULL;
        fileseg->hlen = sizeof(struct fileseg_h) / 4;
    }
    data = (unsigned char *)fileseg + (fileseg->hlen * 4);
    set_uftp_header(header, FILESEG, finfo->group_id, finfo->group_inst,
                    l_adv_grtt, destcount);

    gettimeofday(&start_time, NULL);
    gettimeofday(&last_sent, NULL);
    overage = 0;
    offset = 0;

    lseek_func(file, 0, SEEK_SET);
    fileseg->func = FILESEG;
    fileseg->file_id = htons(finfo->file_id);
    // If all clients received this file partially on a prior attempt,
    // set the block counter at the end so we start by sending a DONE
    if (finfo->partial) {
        block = finfo->blocks;
    } else {
        block = 0;
    }
    done_sent = 0;
    current_nak = 1;
    attempt = 1;
    l_file_done_flag = 0;
    if ((cc_type == CC_NONE) && (rate != -1) && (txweight != 0)) {
        max_time = (int)(0 + floor(((double)txweight / 100) *
                ((double)finfo->size / rate)));
        glog2(finfo, "Maximum file transfer time: %d seconds", max_time);
    } else {
        max_time = 0;
    }
    pass = 1;
    section = 0;
    last_section = (uint16_t)-1;
    glog2(finfo, "Sending file");
    glog2(finfo, "Starting pass %u", pass);
    do {
        if (block < finfo->blocks) {
            if (current_nak) {
                glog5(finfo, "Sending %d, wait=%d", block, l_packet_wait);
                attempt = 1;
                // TODO: try to avoid seek on consecutive packets?
                curr_offset = offset;
                if (!seek_block(finfo, file, block, &curr_offset)) {
                    continue;
                }
                offset = curr_offset;
                if ((numbytes = read(file, data, blocksize)) == -1) {
                    gsyserror(finfo, "read failed");
                    continue;
                }
                offset += numbytes;

                // Keep track of how long we really slept compared to how
                // long we expected to sleep.  If we went over, subtract the
                // time over from the next sleep time.  This way we maintain
                // the proper average sleep time.
                if (l_packet_wait > overage) {
                    usleep(l_packet_wait - (int32_t)overage);
                }
                gettimeofday(&current_sent, NULL);
                tdiff = diff_usec(current_sent, last_sent);
                if (l_packet_wait) overage += tdiff - l_packet_wait;
                last_sent = current_sent;
                if (log_level >= 5) {
                    cglog5(finfo, "tdiff=%s, ", printll(tdiff));
                    slog5("overage=%s", printll(overage));
                }
                // When rate changes significantly, clear the overage counter
                if (l_rate_change) {
                    overage = 0;
                }

                header->grtt = quantize_grtt(l_adv_grtt);
                if (cc_type == CC_TFMCC) {
                    tfmcc->send_rate = htons(quantize_rate(rate));
                    tfmcc->cc_seq = htons(l_cc_seq);
                    tfmcc->cc_rate = htons(quantize_rate(l_cc_rate));
                }

                if (block >= finfo->big_sections * finfo->secsize_big) {
                    fileseg->section = htons(((block -
                            (finfo->big_sections * finfo->secsize_big)) /
                            finfo->secsize_small) + finfo->big_sections);
                    fileseg->sec_block = htons((block -
                            (finfo->big_sections * finfo->secsize_big)) %
                            finfo->secsize_small);
                } else {
                    fileseg->section = htons(block / finfo->secsize_big);
                    fileseg->sec_block = htons(block % finfo->secsize_big);
                }
                section = ntohs(fileseg->section);
                if (last_section != section) {
                    glog2(finfo, "Sending section %u", section);
                    last_section = section;
                }

                send_data(finfo, packet, numbytes, encpacket);
                done_sent = 0;
            }
        } else {
            gettimeofday(&now, NULL);
            if (!done_sent ||
                    (diff_usec(now, last_sent) > (3 * l_adv_grtt * 1000000))) {
                if (attempt < robust) {
                    if (!send_done(finfo, attempt, finfo->sections ?
                                        finfo->sections - 1 : 0, l_adv_grtt)) {
                        glog0(finfo, "Error sending DONE");
                    }
                }
                attempt++;
                gettimeofday(&last_sent, NULL);
                done_sent = 1;
            }
            usleep(l_packet_wait);
            overage = 0;
        }

        // Access anything used by both threads under one mutex all at once
        if (mux_lock(mux_main)) {
            glog0(finfo, "Failed to lock mutex in transfer_send_thread");
            continue;
        }
        if (max_time) {
            gettimeofday(&now, NULL);
            if (diff_sec(now, start_time) > max_time) {
                glog1(finfo, "Maximum file transfer time exceeded");
                max_time_timeout = 1;
                file_done_flag = 1;
            }
        }
        if (block < finfo->blocks) {
            finfo->naklist[block] = 0;
            block++;
        } else {
            end_of_pass = 1;
        }
        if (rewind_flag) {
            glog2(finfo, "Starting pass %u", ++pass);
            block = 0;
            rewind_flag = 0;
            end_of_pass = 0;
            last_section = (uint16_t)-1;
        }
        if (block < finfo->blocks) {
            current_nak = finfo->naklist[block];
        } else {
            current_nak = 0;
        }
        current_position = block;
        if ((attempt > robust) && !rewind_pending_flag) {
            glog1(finfo, "Sending thread timed out");
            file_done_flag = 1;
        }
        l_cc_seq = cc_seq;
        l_cc_rate = cc_rate;
        l_adv_grtt = adv_grtt;
        l_packet_wait = packet_wait;
        l_file_done_flag = file_done_flag;
        l_rate_change = rate_change;
        rate_change = 0;
        get_cc_queue(&cc_body, &cc_len);
        if (mux_unlock(mux_main)) {
            glog0(finfo, "Failed to unlock mutex in transfer_send_thread");
            // TODO: if we can't unlock, kill the thread and fail the file
            continue;
        }

        if (cc_body) {
            send_cong_ctrl(finfo, l_adv_grtt, l_cc_seq, l_cc_rate,
                           cc_body, cc_len);
            free(cc_body);
            cc_body = NULL;
        }
    } while (!l_file_done_flag);

    free(packet);
    free(encpacket);

    THREAD_RETURN;
}

/**
 * Thread for receiving all packets during the transfer phase
 * Called directly from transfer_phase
 */
void transfer_receive_thread(struct finfo_t *finfo)
{
    unsigned char *packet, *decrypted, *cc_body;
    union sockaddr_u receiver;
    struct timeval now, timeout, rewind_time, fb_end, next_cc;
    struct timeval min_tstamp;
    int l_file_done_flag, got_naks, cc_len;
    int alldone, found_error, i, len, rcv_status, found_timeout;
    int do_rewind, do_nextcc, do_halfrate;
    int64_t last_clr;
    double l_adv_grtt;
    uint8_t tos;

    packet = safe_calloc(MAXMTU, 1);
    decrypted = safe_calloc(MAXMTU, 1);

    alldone = 0;
    rewind_time.tv_sec = 0;
    rewind_time.tv_usec = 0;
    got_naks = 0;
    next_cc.tv_sec = 0;
    next_cc.tv_usec = 0;
    // Not mutexed, but should be OK when the thread first starts
    l_adv_grtt = adv_grtt;
    glog4(finfo, "adv_grtt=%.3f", l_adv_grtt);
    if (cc_type == CC_TFMCC) {
        // Start a feedback round
        gettimeofday(&last_clr_time, NULL);
        gettimeofday(&fb_end, NULL);
        add_timeval_d(&fb_end, 6 * l_adv_grtt);
    } else {
        fb_end.tv_sec = 0;
        fb_end.tv_usec = 0;
    }
    l_file_done_flag = 0;
    do {
        do_rewind = 0;
        do_nextcc = 0;
        do_halfrate = 0;
        gettimeofday(&now, NULL);
        if ((cc_type == CC_TFMCC) && (cmptimestamp(now, next_cc) > 0)) {
            create_cc_list(&cc_body, &cc_len); 
            if (!put_cc_queue(finfo, cc_body, cc_len)) {
                glog1(finfo, "Couldn't queue up CONG_CTRL: list full!");
                free(cc_body);
            } else {
                gettimeofday(&next_cc, NULL);
                add_timeval_d(&next_cc, 1 * l_adv_grtt);
            }
            glog3(finfo, "CONG_CTRL queued");

            // TODO: bypass this check if selected less that 10 RTT ago?
            if (diff_usec(now, last_clr_time) > 1000000 * 4 * l_adv_grtt) {
                do_halfrate = 1;
                glog5(finfo, "Halfing rate");
            }
            if (diff_usec(now, last_clr_time) > 1000000 * robust * l_adv_grtt) {
                clr = -1;
                clr_drop = 1;
                glog5(finfo, "Lost clr");
            }
        }
        if ((rewind_time.tv_sec) && (cmptimestamp(now, rewind_time) >= 0)) {
            do_rewind = 1;
        }
        if ((fb_end.tv_sec) && (cmptimestamp(now, fb_end) >= 0)) {
            do_nextcc = 1;
        }
        if (do_rewind || do_nextcc || do_halfrate) {
            if (mux_lock(mux_main)) {
                glog0(finfo, "Failed to lock mutex in transfer_receive_thread "
                             "for rewind / feedback");
                continue;
            }
        }
        if (do_rewind) {
            glog3(finfo, "Rewind timer tripped");
            rewind_flag = 1;
            rewind_time.tv_sec = 0;
            rewind_time.tv_usec = 0;
            got_naks = 0;
            for (i = 0; i < destcount; i++) {
                if (destlist[i].status == DEST_ACTIVE_NAK) {
                    destlist[i].status = DEST_ACTIVE;
                }
            }
        }
        if (do_halfrate) {
            rate /= 2;
            if (rate < datapacketsize / grtt) {
                slowstart = 1;
                rate = (int)(datapacketsize / grtt);
            }
            packet_wait = (int32_t)(1000000.0 * datapacketsize / rate);
            rate_change = 1;
            last_clr = diff_usec(now, last_clr_time);
            if ((last_clr > 1000000 * 2 * robust * l_adv_grtt) &&
                    (last_clr > 1000000 * 5)) {
                // No new CLR chosen in 2*robust RTTs (or 5 seconds) since the
                // prior one dropped, meaning no feedback from anyone, so quit
                glog2(finfo, "No feedback in %d GRTTs", 2 * robust);
                file_done_flag = 1;
            }
        }
        if (do_nextcc) {
            // TODO: Handle extended feedback round
            if (clr_drop) {
                clr_drop = 0;
                if (new_rate) {
                    rate = new_rate;
                }
                packet_wait = (int32_t)(1000000.0 * datapacketsize / rate);
                rate_change = 1;
            }
            recalculate_grtt(finfo, 1, 1);
            adv_grtt = (double)datapacketsize / rate;
            if (adv_grtt < grtt) {
                adv_grtt = grtt;
            }
            l_adv_grtt = adv_grtt;
            glog5(finfo, "adv_grtt=%.3f", l_adv_grtt);
            if (rate < datapacketsize / grtt) {
                slowstart = 1;
                rate = (int)(datapacketsize / grtt);
                packet_wait = (int32_t)(1000000.0 * datapacketsize / rate);
                rate_change = 1;
            }
            gettimeofday(&fb_end, NULL);
            add_timeval_d(&fb_end, 6 * l_adv_grtt);
            cc_rate = 0xFFFFFFFF;
            cc_seq++;
            glog4(finfo, "Starting feedback round %d", cc_seq);
        }
        if (do_rewind || do_nextcc || do_halfrate) {
            if (mux_unlock(mux_main)) {
                glog0(finfo, "Failed to unlock mutex in "
                             "transfer_receive_thread for rewind / feedback");
                continue;
            }
        }
        found_timeout = 0;
        if (rewind_time.tv_sec) {
            min_tstamp = rewind_time;
            found_timeout = 1;
        }
        if (fb_end.tv_sec) {
            if (!found_timeout || (cmptimestamp(fb_end, min_tstamp) < 0)) {
                min_tstamp = fb_end;
                found_timeout = 1;
            }
        }
        if (cc_type == CC_TFMCC) {
            if (!found_timeout || (cmptimestamp(next_cc, min_tstamp) < 0)) {
                min_tstamp = next_cc;
                found_timeout = 1;
            }
        }
        if (found_timeout) {
            timeout = diff_timeval(min_tstamp, now);
        } else {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            add_timeval_d(&timeout, 1 * l_adv_grtt);
        }

        if ((rcv_status = read_packet(sock, &receiver, packet, &len,
                                      MAXMTU, &timeout, &tos)) == -1) {
            continue;
        } else if (rcv_status == 0) {
            // Timeouts get handled at the top of the loop
        } else if (validate_packet(packet, len, finfo)) {
            handle_transfer_phase(packet, decrypted, len, &receiver, finfo,
                                  &got_naks);

            for (i = 0, alldone = 1; (i < destcount) && alldone; i++) {
                alldone = alldone && ((destlist[i].status == DEST_DONE) ||
                        (client_error(i)) || (destlist[i].isproxy));
            }
        }

        if (mux_lock(mux_main)) {
            glog0(finfo, "Failed to lock mutex in transfer_receive_thread");
            continue;
        }
        if (alldone || user_abort) {
            file_done_flag = 1;
        } else if (got_naks && end_of_pass && (rewind_time.tv_sec == 0)) {
            gettimeofday(&rewind_time, NULL);
            add_timeval_d(&rewind_time, 3 * l_adv_grtt);
            glog3(finfo, "Starting rewind timer");
        }
        l_file_done_flag = file_done_flag;
        l_adv_grtt = adv_grtt;
        glog5(finfo, "adv_grtt=%.3f", l_adv_grtt);
        rewind_pending_flag = (rewind_time.tv_sec != 0);
        if (mux_unlock(mux_main)) {
            glog0(finfo, "Failed to unlock mutex in transfer_receive_thread");
            continue;
        }

    } while (!l_file_done_flag);

    found_error = 0;
    if (user_abort || max_time_timeout) {
        glog0(finfo, "Aboring all clients");
        if (user_abort) {
            send_abort(finfo, "Server quit, aborting all",
                       &receive_dest, 0, (keytype != KEY_NONE), 0);
        } else if (max_time_timeout) {
            send_abort(finfo, "Max file transfer time exceeded",
                       &receive_dest, 0, (keytype != KEY_NONE), 0);
        }
        for (i = 0; i < destcount; i++) {
            if ((destlist[i].status == DEST_ACTIVE) ||
                    (destlist[i].status == DEST_ACTIVE_NAK)) {
                destlist[i].status = DEST_ABORT;
            }
        }
    } else if (!alldone) {
        for (i = 0; i < destcount; i++) {
            if ((destlist[i].status == DEST_ACTIVE) ||
                    (destlist[i].status == DEST_ACTIVE_NAK)) {
                glog1(finfo, "No response from %s", destlist[i].name);
                destlist[i].status = DEST_LOST;
                if (quit_on_error && !found_error) {
                    found_error = 1;
                    glog0(finfo, "Aboring all clients");
                    send_abort(finfo, "A client dropped out, aborting all",
                            &receive_dest, 0, (keytype != KEY_NONE), 0);
                }
            }
        }
    }

    free(packet);
    free(decrypted);
}

/**
 * Performs the Transfer phase for a particular file.
 * It sits in a loop to do all reads, and it starts a thread to do all writes
 * Returns 1 if at least one client finished, 0 if all are dropped or aborted
 * Returns ERR_NONE if at least one client responded, ERR_DROPPED otherwise
 */
int transfer_phase(struct finfo_t *finfo)
{
    thread_t tid;
    int alldone, i;
    double tmp_rtt;
    uint32_t nak;
    char path[MAXPATHNAME];
    struct timeval start_time;

    // First check to see if all clients are already done for this file.
    // This can happen on a restart when the file finished on the
    // last attempt and responded to the FILEINFO with a COMPLETE
    for (i = 0, alldone = 1; (i < destcount) && alldone; i++) {
        alldone = alldone && ((destlist[i].status == DEST_DONE) ||
                    (client_error(i)) || (destlist[i].isproxy));
    }
    if (alldone) {
        gettimeofday(&start_time, NULL);
        print_status(finfo, start_time);
        return ERR_NONE;
    }

    // TODO: if not a regular file, error any clients that didn't
    // respond to the FILEINFO with a COMPLETE
    if (finfo->ftype == FTYPE_REG) {
        snprintf(path, sizeof(path), "%s%c%s", finfo->basedir, PATH_SEP,
                                               finfo->filename);
        // Open the file now so we don't start the sending thread if it fails
        if ((file = open(path, OPENREAD, 0)) == -1) {
            gsyserror(finfo, "Error opening file");
            return ERR_DROPPED;
        }
    } else {
        // At end of group, all non-errored client are DEST_DONE from the
        // last file, so reset them to DEST_ACTIVE to get the final COMPLETE.
        for (i = 0; i < destcount; i++) {
            if (!client_error(i)) {
                destlist[i].status = DEST_ACTIVE;
                destlist[i].max_nak_exceed = 0;
            }
        }
    }

    gettimeofday(&start_time, NULL);
    max_time_timeout = 0;
    file_done_flag = 0;
    rewind_flag = 0;
    cc_queue_start = 0;
    cc_queue_end = 0;
    rate_change = 0;
    end_of_pass = 0;
    if (cc_type == CC_TFMCC) {
        // Initialize rate to 1 packet per GRTT
        rate = (int32_t)(((double)datapacketsize / grtt));
        packet_wait = (int32_t)(1000000.0 * datapacketsize / rate);
        adv_grtt = (double)datapacketsize / rate;
        if (adv_grtt < grtt) {
            adv_grtt = grtt;
        }
        cc_seq = 0;
        cc_rate = 0xFFFFFFFF;
        slowstart = 1;
        // Pick an initial CLR based on who has the highest RTT
        for (tmp_rtt = 9999, clr = -1, i = 0; i < destcount; i++) {
            if (!client_error(i) && (!destlist[i].isproxy) &&
                    (destlist[i].rtt < tmp_rtt)) {
                clr = i;
                tmp_rtt = destlist[i].rtt;
            }
        }
    } else {
        adv_grtt = grtt;
    }
    for (nak = 0; nak < finfo->blocks; nak++) {
        if (finfo->partial) {
            finfo->naklist[nak] = 0;
        } else {
            finfo->naklist[nak] = 1;
        }
    }
    if (mux_create(mux_main)) {
        gsyserror(finfo, "Failed to create mutex");
        if (finfo->ftype == FTYPE_REG) {
            close(file);
        }
        return ERR_DROPPED;
    }
    use_log_mux = 1;

    if (start_thread(tid, transfer_send_thread, finfo) != 0) {
        gsyserror(finfo, "Failed to create sender thread");
        if (finfo->ftype == FTYPE_REG) {
            close(file);
        }
        mux_destroy(mux_main);
        return ERR_DROPPED;
    }
    transfer_receive_thread(finfo);
    if (join_thread(tid) != 0) {
        gsyserror(finfo, "Failed to join sender thread");
    } else  {
        destroy_thread(tid);
    }
    use_log_mux = 0;

    if (finfo->ftype == FTYPE_REG) {
        close(file);
    }
    mux_destroy(mux_main);
    print_status(finfo, start_time);

    if (user_abort) {
        return ERR_INTERRUPTED;
    }
    for (i = 0; i < destcount; i++) {
        if (quit_on_error) {
            // Check to see that all finished
            if ((destlist[i].status != DEST_DONE) && (!destlist[i].isproxy)) {
                return ERR_DROPPED;
            }
        } else {
            // Check to see if at least one finished
            if (destlist[i].status == DEST_DONE) {
                return ERR_NONE;
            }
        }
    }
    if (quit_on_error) {
        return ERR_NONE;
    } else {
        return ERR_DROPPED;
    }
}

/**
 * Check a completion phase message and pass to appropriate message handler,
 * decrypting first if necessary
 */
void handle_completion_phase(unsigned char *packet,
                             unsigned char *decrypted, int packetlen,
                             const union sockaddr_u *receiver,
                             struct finfo_t *finfo)
{
    struct uftp_h *header;
    unsigned char *message;
    int hostidx;
    unsigned int decryptlen, meslen;
    uint8_t *func;

    header = (struct uftp_h *)packet;
    hostidx = find_client(header->src_id);
    if ((keytype != KEY_NONE) && (header->func == ENCRYPTED)) {
        if (hostidx == -1) {
            glog1(finfo, "Host %08X not in host list", ntohl(header->src_id));
            send_abort(finfo, "Not in host list", receiver, header->src_id,0,0);
            return;
        }
        if (!validate_and_decrypt(packet, packetlen, &decrypted, &decryptlen,
                keytype, groupkey, groupsalt, ivlen, hashtype, grouphmackey,
                hmaclen, sigtype, keyextype, destlist[hostidx].encinfo->pubkey,
                destlist[hostidx].encinfo->pubkeylen)) {
            glog1(finfo, "Rejecting message from %s: "
                         "decrypt/validate failed", destlist[hostidx].name);
            return;
        }
        func = (uint8_t *)decrypted;
        message = decrypted;
        meslen = decryptlen;
    } else {
        if ((keytype != KEY_NONE) && ( (header->func == STATUS) ||
                (header->func == COMPLETE) || (header->func == ABORT))) {
            glog1(finfo, "Rejecting %s message from %08X: not encrypted",
                         func_name(header->func), ntohl(header->src_id));
            return;
        }
        func = (uint8_t *)&header->func;
        message = packet + sizeof(struct uftp_h);
        meslen = packetlen - sizeof(struct uftp_h);
    }

    if (*func == ABORT) {
        handle_abort(message, meslen, hostidx, finfo, header->src_id);
    } else if (hostidx == -1) {
        glog1(finfo, "Host %08X not in host list", ntohl(header->src_id));
        send_abort(finfo, "Not in host list", receiver, header->src_id, 0, 0);
    } else if (*func == COMPLETE) {
        handle_complete(message, meslen, finfo, hostidx);
    } else {
        glog1(finfo, "Received invalid message %s from %s",
                     func_name(*func), destlist[hostidx].name);
    }
    return;
}

/**
 * Performs the Completion/Confirmation phase at the end of a group
 */
void completion_phase(struct finfo_t *finfo)
{
    unsigned char *packet, *decrypted;
    struct timeval timeout, next_send, now, start_time;
    union sockaddr_u receiver;
    int resend, attempt, last_pass, alldone;
    int rcv_status, len, i;
    uint8_t tos;

    packet = safe_calloc(MAXMTU, 1);
    decrypted = safe_calloc(MAXMTU, 1);

    // At end of group, all non-errored client are DEST_DONE from the
    // last file, so reset them to DEST_ACTIVE to get the final COMPLETE.
    for (i = 0; i < destcount; i++) {
        if (!client_error(i)) {
            destlist[i].status = DEST_ACTIVE;
        }
    }

    glog2(finfo, "Finishing group");
    gettimeofday(&start_time, NULL);
    gettimeofday(&next_send, NULL);
    add_timeval_d(&next_send, 3 * grtt);
    resend = 1;
    attempt = 1;
    last_pass = 0;
    while (attempt <= robust) {
        if (user_abort) break;
        if (resend) {
            if (!send_doneconf(finfo, attempt)) {
                continue;
            }
            if (!send_done(finfo, attempt, 0, grtt)) {
                continue;
            }
            resend = 0;
        }
        gettimeofday(&now, NULL);
        if (cmptimestamp(now, next_send) >= 0) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } else {
            timeout = diff_timeval(next_send, now);
        }
        if ((rcv_status = read_packet(sock, &receiver, packet, &len,
                                      MAXMTU, &timeout, &tos)) == -1) {
            continue;
        } else if (rcv_status == 0) {
            attempt++;
            recalculate_grtt(finfo, 1, 0);
            gettimeofday(&next_send, NULL);
            add_timeval_d(&next_send, 3 * grtt);
            resend = 1;
            if (last_pass) break;
            continue;
        }
        if (!validate_packet(packet, len, finfo)) {
            continue;
        }

        handle_completion_phase(packet, decrypted, len, &receiver, finfo);
        for (i = 0, alldone = 1; (i < destcount) && alldone; i++) {
            alldone = alldone && ((destlist[i].status == DEST_DONE) ||
                            (client_error(i)) || (destlist[i].isproxy));
        }
        if (alldone) {
            // Change the timeout to 1 * grtt
            // to allow for late completions
            recalculate_grtt(finfo, 1, 0);
            gettimeofday(&next_send, NULL);
            add_timeval_d(&next_send, grtt);
            if (!last_pass) {
                glog2(finfo, "Late completions:");
            }
            last_pass = 1;
            send_doneconf(finfo, attempt + 1);
        } 
    }
    for (i = 0; i < destcount; i++) {
        if (destlist[i].status == DEST_ACTIVE) {
            glog1(finfo, "Couldn't get COMPLETE for group from %s",
                         destlist[i].name);
            destlist[i].status = DEST_LOST;
        }
    }

    send_doneconf(finfo, attempt + 1);
    print_status(finfo, start_time);

    free(packet);
    free(decrypted);
}

