/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2012   Dennis A. Bush, Jr.   bush@tcnj.edu
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

#ifndef _SERVER_ANNOUNCE_H
#define _SERVER_ANNOUNCE_H

#include "server.h"

int send_announce(const struct finfo_t *finfo, int attempt, int open);
int send_regconf(const struct finfo_t *finfo, int attempt, int do_regconf);
int send_keyinfo(const struct finfo_t *finfo, int attempt);
int send_fileinfo(const struct finfo_t *finfo, int attempt);

void handle_open_register(const unsigned char *message, unsigned meslen,
                          struct finfo_t *finfo, const union sockaddr_u *su,
                          uint32_t src, int regconf);
void handle_register(const unsigned char *message, unsigned meslen,
                     struct finfo_t *finfo, const union sockaddr_u *su,
                     int hostidx, int regconf, int open);
void handle_open_clientkey(const unsigned char *message, unsigned meslen,
                           struct finfo_t *finfo, const union sockaddr_u *su,
                           uint32_t src);
void handle_clientkey(const unsigned char *message, unsigned meslen,
                      struct finfo_t *finfo, const union sockaddr_u *su,
                      int hostidx);
void handle_keyinfo_ack(const unsigned char *message, unsigned meslen,
                        struct finfo_t *finfo, const union sockaddr_u *su,
                        int hostidx);
void handle_fileinfo_ack(const unsigned char *message, unsigned meslen,
                         struct finfo_t *finfo, int hostidx);

#endif  // _SERVER_ANNOUNCE_H

