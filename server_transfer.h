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

#ifndef _SERVER_TRANSFER_H
#define _SERVER_TRANSFER_H

#include "server.h"

int send_doneconf(const struct finfo_t *finfo, int attempt);
int send_done(const struct finfo_t *finfo, int attempt, int section,
              double l_grtt);
void create_cc_list(unsigned char **body, int *len);
void send_cong_ctrl(const struct finfo_t *finfo, double l_grtt,
                    uint16_t l_cc_seq, uint32_t l_cc_rate,
                    unsigned char *body, int len);

void handle_complete(const unsigned char *message, unsigned meslen,
                     struct finfo_t *finfo, int hostidx);
void handle_status(const unsigned char *message, unsigned meslen,
                   struct finfo_t *finfo, int hostidx, int *got_naks);
void handle_cc_ack(const unsigned char *message, unsigned meslen,
                   struct finfo_t *finfo, int hostidx);

int send_data(const struct finfo_t *finfo, unsigned char *packet, int datalen,
              unsigned char *encpacket);
void print_status(const struct finfo_t *finfo, struct timeval start_time);

#endif  // _SERVER_TRANSFER_H

