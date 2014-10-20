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

#ifndef _ENCRYPTION_H
#define _ENCRYPTION_H

// This section includes items normally listed in uftp_common.h
// that are required in encrypt_cng.c.  See encrypt_cng.c for more details.
#ifdef NO_UFTP_COMMON_H

#include <stdio.h>
extern int showtime;
extern FILE *applog;
extern int log_level;

void logfunc(uint32_t group_id, uint16_t file_id, int level, int _showtime,
             int newline, int err, int sockerr, const char *str, ...);

#define clog0(group_id, file_id, ...) \
    logfunc(group_id, file_id, 0, showtime, 0, 0, 0, __VA_ARGS__)
#define log0(group_id, file_id, ...) \
    logfunc(group_id, file_id, 0, showtime, 1, 0, 0, __VA_ARGS__)
#define sclog2(...) \
    logfunc(0, 0, 2, 0, 0, 0, 0, __VA_ARGS__)
#define syserror(group_id, file_id, ...) \
    logfunc(group_id, file_id, 0, showtime, 1, errno, 0, __VA_ARGS__)

int is_auth_enc(int keytype);
int is_gcm_mode(int keytype);
int is_ccm_mode(int keytype);

void *safe_malloc(size_t size);
void *safe_calloc(size_t num, size_t size);

#endif

#ifdef NO_ENCRYPTION

typedef void *RSA_key_t;
typedef void *EC_key_t;

#elif defined WINDOWS && !defined OPENSSL &&\
    (_WIN32_WINNT >= _WIN32_WINNT_LONGHORN)

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
typedef NCRYPT_KEY_HANDLE RSA_key_t;
typedef NCRYPT_KEY_HANDLE EC_key_t;

#elif defined WINDOWS && !defined OPENSSL

#include <windows.h>
#include <wincrypt.h>
typedef HCRYPTKEY RSA_key_t;
typedef void *EC_key_t;

#else

#include <openssl/rsa.h>
typedef RSA *RSA_key_t;

#ifndef NO_EC
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
typedef EC_KEY *EC_key_t;
#else
typedef void *EC_key_t;
#endif

#endif

union key_t {
    uint64_t key;
    RSA_key_t rsa;
    EC_key_t ec;
};

void crypto_init(int set_sys_key);

void crypto_cleanup(void);

int cipher_supported(int keytype);

int hash_supported(int hashtype);

void get_key_info(int keytype, int *keylen, int *ivlen);

int get_hash_len(int hashtype);

int get_random_bytes(unsigned char *buf, int num);

int encrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *aad, unsigned int aadlen,
                  const unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen);

int decrypt_block(int keytype, const unsigned char *IV,
                  const unsigned char *key,
                  const unsigned char *aad, unsigned int aadlen,
                  unsigned char *src, unsigned int srclen,
                  unsigned char *dest, unsigned int *destlen);

int create_hmac(int hashtype, const unsigned char *key, unsigned int keylen,
                const unsigned char *src, unsigned int srclen,
                unsigned char *dest, unsigned int *destlen);

int hash(int hashtype, const unsigned char *src, unsigned int srclen,
         unsigned char *dest, unsigned int *destlen);

int RSA_keylen(const RSA_key_t rsa);

int EC_keylen(const EC_key_t ec);

int ECDSA_siglen(const EC_key_t ec);

int RSA_encrypt(RSA_key_t rsa, const unsigned char *from, unsigned int fromlen,
                unsigned char *to, unsigned int *tolen);

int RSA_decrypt(RSA_key_t rsa, const unsigned char *from, unsigned int fromlen,
                unsigned char *to, unsigned int *tolen);

int create_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int *siglen);

int verify_RSA_sig(RSA_key_t rsa, int hashtype,
                   const unsigned char *mes, unsigned int meslen,
                   unsigned char *sig, unsigned int siglen);

int create_ECDSA_sig(EC_key_t ec, int hashtype,
                     const unsigned char *mes, unsigned int meslen,
                     unsigned char *sig, unsigned int *siglen);

int verify_ECDSA_sig(EC_key_t ec, int hashtype,
                     const unsigned char *mes, unsigned int meslen,
                     const unsigned char *sig, unsigned int siglen);

int get_ECDH_key(EC_key_t pubkey, EC_key_t privkey, unsigned char *key,
                 unsigned int *keylen);

int import_RSA_key(RSA_key_t *rsa, const unsigned char *keyblob,
                   uint16_t bloblen);

int export_RSA_key(const RSA_key_t rsa, unsigned char *keyblob,
                   uint16_t *bloblen);

int import_EC_key(EC_key_t *ec, const unsigned char *keyblob, uint16_t bloblen,
                  int isdh);

int export_EC_key(const EC_key_t ec, unsigned char *keyblob, uint16_t *bloblen);

RSA_key_t gen_RSA_key(int bits, int exponent, const char *filename);

RSA_key_t read_RSA_key(const char *filename);

EC_key_t gen_EC_key(uint8_t curve, int isdh, const char *filename);

EC_key_t read_EC_key(const char *filename);

union key_t read_private_key(const char *filename, int *keytype);

uint8_t get_EC_curve(const EC_key_t ec);

void free_RSA_key(RSA_key_t rsa);

void free_EC_key(EC_key_t ec);

const char *get_next_container(void);

void delete_container(const char *name);

void set_sys_keys(int set);


#endif  // _ENCRYPTION_H

