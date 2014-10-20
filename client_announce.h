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

#ifndef _CLIENT_ANNOUNCE_H
#define _CLIENT_ANNOUNCE_H

void handle_announce(union sockaddr_u *src, unsigned char *packet,
                     unsigned packetlen, struct timeval rxtime);
void handle_keyinfo(struct group_list_t *group, unsigned char *message,
                    unsigned meslen, uint32_t src_id);
void handle_regconf(struct group_list_t *group, const unsigned char *message,
                    unsigned meslen);
void send_register(struct group_list_t *group);
void send_keyinfo_ack(struct group_list_t *group);

#endif  // _CLIENT_ANNOUNCE_H
