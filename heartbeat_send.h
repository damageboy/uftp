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

#ifndef _HEARTBEAT_SEND_H
#define _HEARTBEAT_SEND_H

void handle_hb_response(SOCKET s, const union sockaddr_u *src,
                        const unsigned char *message, unsigned meslen,
                        union sockaddr_u hb_hosts[], int num_hosts,
                        union key_t privkey, int keytype, uint32_t uid);
void send_auth_hb_request(SOCKET s, union sockaddr_u *hbhost, uint32_t nonce,
                          union key_t privkey, int keytype, uint32_t uid);
void send_hb_request(SOCKET s, union sockaddr_u hb_hosts[], int num_hosts,
                     struct timeval *next_hb_time, int hb_interval,
                     uint32_t uid);

#endif  // _HEARTBEAT_SEND_H

