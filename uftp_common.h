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

#ifndef _UFTP_COMMON_H
#define _UFTP_COMMON_H

#include <stdio.h>

#ifdef WINDOWS

#include <winsock2.h>
#include <ws2tcpip.h>

#else

#include <netinet/in.h>

#endif

#include "uftp.h"
#include "encryption.h"

#define DEF_LOG_LEVEL 2
#define DEF_MAX_LOG_COUNT 5

extern char logfile[MAXPATHNAME];
extern int showtime;
extern FILE *applog;
extern int log_level, init_log_mux, use_log_mux, max_log_count;
extern f_offset_t log_size, max_log_size;
extern mux_t log_mux;

void init_log(int _debug);
void close_log(void);
void roll_log(void);
void logfunc(uint32_t group_id, uint8_t group_inst, uint16_t file_id,
             int level, int _showtime, int newline, int err, int sockerr,
             const char *str, ...);

#define GRPLOG(group) (group)->group_id, (group)->group_inst, (group)->file_id

#define clog0(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 0, showtime, 0, 0, 0, __VA_ARGS__)
#define log0(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 0, showtime, 1, 0, 0, __VA_ARGS__)
#define cglog0(group, ...) \
    logfunc(GRPLOG(group), 0, showtime, 0, 0, 0, __VA_ARGS__)
#define glog0(group, ...) \
    logfunc(GRPLOG(group), 0, showtime, 1, 0, 0, __VA_ARGS__)
#define sclog0(...) \
    logfunc(0, 0, 0, 0, 0, 0, 0, 0, __VA_ARGS__)
#define slog0(...) \
    logfunc(0, 0, 0, 0, 0, 1, 0, 0, __VA_ARGS__)

#define clog1(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 1, showtime, 0, 0, 0, __VA_ARGS__)
#define log1(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 1, showtime, 1, 0, 0, __VA_ARGS__)
#define cglog1(group, ...) \
    logfunc(GRPLOG(group), 1, showtime, 0, 0, 0, __VA_ARGS__)
#define glog1(group, ...) \
    logfunc(GRPLOG(group), 1, showtime, 1, 0, 0, __VA_ARGS__)
#define sclog1(...) \
    logfunc(0, 0, 0, 1, 0, 0, 0, 0, __VA_ARGS__)
#define slog1(...) \
    logfunc(0, 0, 0, 1, 0, 1, 0, 0, __VA_ARGS__)

#define clog2(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 2, showtime, 0, 0, 0, __VA_ARGS__)
#define log2(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 2, showtime, 1, 0, 0, __VA_ARGS__)
#define cglog2(group, ...) \
    logfunc(GRPLOG(group), 2, showtime, 0, 0, 0, __VA_ARGS__)
#define glog2(group, ...) \
    logfunc(GRPLOG(group), 2, showtime, 1, 0, 0, __VA_ARGS__)
#define sclog2(...) \
    logfunc(0, 0, 0, 2, 0, 0, 0, 0, __VA_ARGS__)
#define slog2(...) \
    logfunc(0, 0, 0, 2, 0, 1, 0, 0, __VA_ARGS__)

#define clog3(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 3, showtime, 0, 0, 0, __VA_ARGS__)
#define log3(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 3, showtime, 1, 0, 0, __VA_ARGS__)
#define cglog3(group, ...) \
    logfunc(GRPLOG(group), 3, showtime, 0, 0, 0, __VA_ARGS__)
#define glog3(group, ...) \
    logfunc(GRPLOG(group), 3, showtime, 1, 0, 0, __VA_ARGS__)
#define sclog3(...) \
    logfunc(0, 0, 0, 3, 0, 0, 0, 0, __VA_ARGS__)
#define slog3(...) \
    logfunc(0, 0, 0, 3, 0, 1, 0, 0, __VA_ARGS__)

#define clog4(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 4, showtime, 0, 0, 0, __VA_ARGS__)
#define log4(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 4, showtime, 1, 0, 0, __VA_ARGS__)
#define cglog4(group, ...) \
    logfunc(GRPLOG(group), 4, showtime, 0, 0, 0, __VA_ARGS__)
#define glog4(group, ...) \
    logfunc(GRPLOG(group), 4, showtime, 1, 0, 0, __VA_ARGS__)
#define sclog4(...) \
    logfunc(0, 0, 0, 4, 0, 0, 0, 0, __VA_ARGS__)
#define slog4(...) \
    logfunc(0, 0, 0, 4, 0, 1, 0, 0, __VA_ARGS__)

#define clog5(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 5, showtime, 0, 0, 0, __VA_ARGS__)
#define log5(group_id, group_inst, file_id, ...) \
    logfunc(group_id, group_inst, file_id, 5, showtime, 1, 0, 0, __VA_ARGS__)
#define cglog5(group, ...) \
    logfunc(GRPLOG(group), 5, showtime, 0, 0, 0, __VA_ARGS__)
#define glog5(group, ...) \
    logfunc(GRPLOG(group), 5, showtime, 1, 0, 0, __VA_ARGS__)
#define sclog5(...) \
    logfunc(0, 0, 0, 5, 0, 0, 0, 0, __VA_ARGS__)
#define slog5(...) \
    logfunc(0, 0, 0, 5, 0, 1, 0, 0, __VA_ARGS__)

#define syserror(group_id, group_inst, file_id, ...) \
    logfunc(group_id,group_inst, file_id, 0, showtime, 1, errno, 0, __VA_ARGS__)
#define sockerror(group_id, group_inst, file_id, ...) \
    logfunc(group_id,group_inst, file_id, 0, showtime, 1, errno, 1, __VA_ARGS__)
#define gsyserror(group, ...) \
    logfunc(GRPLOG(group), 0, showtime, 1, errno, 0, __VA_ARGS__)
#define gsockerror(group, ...) \
    logfunc(GRPLOG(group), 0, showtime, 1, errno, 1, __VA_ARGS__)

union sockaddr_u {
    struct sockaddr_storage ss;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

struct iflist {
    char name[IFNAME_LEN];
    union sockaddr_u su;
    int isloopback;
    int ismulti;
    int ifidx;
};

const char *func_name(int func);
const char *curve_name(int curve);
uint8_t get_curve(const char *name);
int32_t diff_sec(struct timeval t2, struct timeval t1);
int64_t diff_usec(struct timeval t2, struct timeval t1);
int cmptimestamp(struct timeval t1, struct timeval t2);
struct timeval add_timeval(struct timeval t2, struct timeval t1);
void add_timeval_d(struct timeval *t2, double t1);
struct timeval diff_timeval(struct timeval t2, struct timeval t1);
const char *printll(int64_t n);
void getiflist(struct iflist *list, int *len);
void split_path(const char *path, char **dir, char **file);
int parse_fingerprint(unsigned char *fingerprint, const char *fingerprint_str);
int is_multicast(const union sockaddr_u *addr, int ssm);
int addr_equal(const union sockaddr_u *addr1, const union sockaddr_u *addr2);
int addr_blank(const union sockaddr_u *addr);
uint64_t uftp_htonll(uint64_t val);
uint64_t uftp_ntohll(uint64_t val);

int family_len(union sockaddr_u addr);
int would_block_err(void);
int nb_sendto(SOCKET s, const void *msg, int len, int flags,
              const struct sockaddr *to, int tolen);
int read_packet(SOCKET sock, union sockaddr_u *sa, unsigned char *buffer,
                int *len, int bsize, const struct timeval *timeout,
                uint8_t *tos);
void build_iv(uint8_t *iv, const uint8_t *salt, int ivlen, uint64_t ivctr,
              uint32_t src_id);
void printhex(const char *name, const unsigned char *data, int len);
int is_auth_enc(int keytype);
int is_gcm_mode(int keytype);
int is_ccm_mode(int keytype);
int unauth_key(int keytype);
int encrypt_and_sign(const unsigned char *decpacket, unsigned char **encpacket,
                     int declen, int *enclen, int keytype, uint8_t *key, 
                     const uint8_t *salt, uint64_t *ivctr, int ivlen,
                     int hashtype, uint8_t *hmackey, uint8_t hmaclen,
                     int sigtype, int keyextype, union key_t privkey,
                     int privkeylen);
int validate_and_decrypt(unsigned char *encpacket, unsigned int enclen,
                         unsigned char **decpacket, unsigned int *declen,
                         int keytype, const uint8_t *key,
                         const uint8_t *salt, int ivlen, int hashtype,
                         const uint8_t *hmackey, uint8_t hmaclen, int sigtype,
                         int keyextype, union key_t pubkey, int pubkeylen);
void PRF(int hashtype, int bytes, const unsigned char *secret, int secret_len,
         const char *label, const unsigned char *seed, int seed_len,
         unsigned char *outbuf, int *outbuf_len);
const char *print_key_fingerprint(const union key_t key, int keytype);

/**
 * Key fingerprint for an allowed server or client
 */
struct fp_list_t {
    uint32_t uid;
    union sockaddr_u addr;
    int has_fingerprint;
    uint8_t fingerprint[HMAC_LEN];
};

int multicast_join(SOCKET s, uint32_t group_id, const union sockaddr_u *multi,
                   const struct iflist *addrlist, int addrlen,
                   const struct fp_list_t *fplist, int fplist_len);
void multicast_leave(SOCKET s, uint32_t group_id, const union sockaddr_u *multi,
                     const struct iflist *addrlist, int addrlen,
                     const struct fp_list_t *fplist, int fplist_len);

int getifbyname(const char *name, const struct iflist *list, int len);
int getifbyaddr(union sockaddr_u *su, const struct iflist *list, int len);

int file_read(int fd, void *buf, int buflen, int allow_eof);
int file_write(int fd, const void *buf, int buflen);
int64_t free_space(const char *dir);

int valid_priority(int priority);
uint32_t rand32(void);
void *safe_malloc(size_t size);
void *safe_calloc(size_t num, size_t size);

uint8_t quantize_grtt(double rtt);
double unquantize_grtt(uint8_t rtt);
uint8_t quantize_gsize(int size);
int unquantize_gsize(uint8_t size);
uint16_t quantize_rate(uint32_t size);
uint32_t unquantize_rate(uint16_t size);

#endif  // _UFTP_COMMON_H

