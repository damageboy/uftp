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

#ifndef _CLIENT_COMMON_H
#define _CLIENT_COMMON_H

struct group_list_t *find_group(uint32_t group_id, uint8_t group_inst);
int uid_in_list(const uint32_t *addrlist, int size);
void read_restart_file(struct group_list_t *group);
void run_postreceive_multi(struct group_list_t *group, char *const *files,
                           int count);
void run_postreceive(struct group_list_t *group, char *file);
int other_mcast_users(struct group_list_t *group);
void file_cleanup(struct group_list_t *group, int abort);
int flush_disk_cache(struct group_list_t *group);
void set_uftp_header(struct uftp_h *header, int func,
                     struct group_list_t *group);
void set_timeout(struct group_list_t *group, int rescale);
void send_abort(struct group_list_t *group, const char *message);
void handle_abort(struct group_list_t *group, const unsigned char *message,
                  unsigned meslen);
void send_key_req(void);
void handle_proxy_key(const union sockaddr_u *src,
                      unsigned char *message, unsigned meslen);
void clear_path(const char *path, struct group_list_t *group);
void move_to_backup(struct group_list_t *group);
int create_path_to_file(struct group_list_t *group, const char *filename);
void update_loss_history(struct group_list_t *group, uint16_t txseq, int size,
                         int ecn);
double loss_event_rate(struct group_list_t *group);
unsigned current_cc_rate(struct group_list_t *group);

#endif  // _CLIENT_COMMON_H

