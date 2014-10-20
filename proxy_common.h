/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2014   Dennis A. Bush, Jr.   bush@tcnj.edu
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

#ifndef _PROXY_COMMON_H
#define _PROXY_COMMON_H

int other_mcast_users(struct pr_group_list_t *group);
struct pr_group_list_t *find_group(uint32_t group_id, uint8_t group_inst);
int find_client(struct pr_group_list_t *group, uint32_t addr);
void group_cleanup(struct pr_group_list_t *group);
void set_uftp_header(struct uftp_h *header, int func,
                     struct pr_group_list_t *group);
void set_timeout(struct pr_group_list_t *group, int pending_reset, int rescale);

int max_msg_dest(struct pr_group_list_t *group, int func, int hlen);
void send_all_pending(struct pr_group_list_t *group);
void check_pending(struct pr_group_list_t *group, int hostdix,
                   const unsigned char *message);
int load_pending(struct pr_group_list_t *group, int pendidx, int func,
                 uint32_t *addrlist, int listlen);
int check_unfinished_clients(struct pr_group_list_t *group, int abort);

void forward_message(struct pr_group_list_t *group,
                     const union sockaddr_u *src,
                     unsigned char *packet, int packetlen);
void handle_hb_request(const union sockaddr_u *src,
                       unsigned char *packet, unsigned packetlen);
void handle_key_req(const union sockaddr_u *src,
                    const unsigned char *packet, unsigned packetlen);
void handle_abort(struct pr_group_list_t *group, const union sockaddr_u *src,
                  const unsigned char *message, unsigned meslen,
                  uint32_t src_id);
void send_upstream_abort(struct pr_group_list_t *group, uint32_t dest_id,
                         const char *message);
void send_downstream_abort(struct pr_group_list_t *group, uint32_t dest_id,
                           const char *message, int current);
void send_hb_response(const union sockaddr_u *src, int response);
void send_proxy_key(void);

int verify_fingerprint(const struct fp_list_t *fplist, int listlen,
                       const unsigned char *keyblob, uint16_t bloblen,
                       struct pr_group_list_t *group, uint32_t id);
uint8_t *build_verify_data(struct pr_group_list_t *group, int hostidx,
                           int *verifylen, int full);
void add_naks_to_pending(struct pr_group_list_t *group, int pendidx,
                         const unsigned char *message);

#endif  // _PROXY_COMMON_H

