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

#ifndef _UFTP_H
#define _UFTP_H

#ifdef WINDOWS

// same as passing /D _CRT_SECURE_NO_WARNINGS to cl
#pragma warning(disable: 4996)

#include <windows.h>
#include <process.h>

typedef unsigned __int8 uint8_t;
typedef __int8 int8_t;
typedef unsigned __int16 uint16_t;
typedef __int16 int16_t;
typedef unsigned __int32 uint32_t;
typedef __int32 int32_t;
typedef unsigned __int64 uint64_t;
typedef __int64 int64_t;

#define open(name, ...) _open(name, __VA_ARGS__)
#define read(fd, buf, count) _read(fd, buf, count)
#define close(fd) _close(fd)
#define write(fd, buf, count) _write(fd, buf, count)
#define dup2(fd1, fd2) _dup2(fd1, fd2)
#define unlink(file) _unlink(file)
#define rmdir(dir) _rmdir(dir)
#define getpid() _getpid()
#define mkdir(dir, mode) _mkdir(dir)
#define usleep(t) Sleep((t)/1000)
#define sleep(t) Sleep((t)*1000)
#define strdup(p) _strdup(p)
#define utime(f, t) _utime(f, t)
#define isfullpath(str) (((str[1] == ':') && (str[2] == '\\')) || \
                         ((str[0] == '\\') && (str[1] == '\\')))
#define PATH_SEP '\\'

typedef int64_t f_offset_t;
typedef struct _stat32i64 stat_struct;
typedef struct _utimbuf utim_buf;
#define stat_func(name, buf) _stat32i64(name, buf)
#define lstat_func(name, buf) _stat32i64(name, buf)
#define S_ISCHR(mode)   (((mode) & S_IFMT) == S_IFCHR)
#define S_ISDIR(mode)   (((mode) & S_IFMT) == S_IFDIR)
#define S_ISREG(mode)   (((mode) & S_IFMT) == S_IFREG)
#define lseek_func(fd, offset, whence) _lseeki64(fd, offset, whence)
#define snprintf(buf, cnt, ...) _snprintf(buf, cnt, __VA_ARGS__)


typedef int socklen_t;
#define OPENREAD (O_RDONLY | O_BINARY)
#define OPENWRITE (O_WRONLY | O_BINARY)

typedef HANDLE mux_t;
#define mux_create(mux) (((mux=CreateMutex(NULL,FALSE,NULL))!=NULL)?0:-1)
#define mux_destroy(mux) ((CloseHandle(mux)!=0)?0:-1)
#define mux_lock(mux) ((WaitForSingleObject(mux,INFINITE)!=WAIT_FAILED)?0:-1)
#define mux_unlock(mux) ((ReleaseMutex(mux)!=0)?0:-1)

typedef unsigned long thread_t;
#define start_thread(id,func,arg) (((id=_beginthread(func,0,arg))!=-1)?0:-1)
#define end_thread() _endthread()
#define thread_id() GetCurrentThreadId()
#define join_thread(id) WaitForSingleObject((HANDLE)(id), INFINITE)
#define destroy_thread(id) CloseHandle((HANDLE)(id))
#define THREAD_FUNC void
#define THREAD_RETURN return

#else  // if WINDOWS

#include <inttypes.h>
#include <pthread.h>


#define closesocket(s) close(s)

#ifdef VMS
pid_t GENERIC_SETSID(void);
#define setsid GENERIC_SETSID
#define fork vfork
typedef unsigned int socklen_t;
#define isfullpath(str) (1)
#define PATH_SEP ':'
#define open(name, flag, mode) open(name, flag, mode, "ctx=stm")
#else
#define isfullpath(str) (str[0] == '/')
#define PATH_SEP '/'
#endif

typedef int64_t f_offset_t;
typedef struct stat stat_struct;
typedef struct utimbuf utim_buf;
#define stat_func(name, buf) stat(name, buf)
#define lstat_func(name, buf) lstat(name, buf)
#define lseek_func(fd, offset, whence) lseek(fd, offset, whence)

typedef int SOCKET;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif
#define OPENREAD (O_RDONLY)
#define OPENWRITE (O_WRONLY)

typedef pthread_mutex_t mux_t;
#define mux_create(mux) pthread_mutex_init(&(mux),NULL)
#define mux_destroy(mux) pthread_mutex_destroy(&(mux))
#define mux_lock(mux) pthread_mutex_lock(&(mux))
#define mux_unlock(mux) pthread_mutex_unlock(&(mux))

typedef pthread_t thread_t;
#define start_thread(id,func,arg) pthread_create(&(id),NULL,func,arg)
#define end_thread() pthread_exit(NULL)
#define thread_id() pthread_self()
#define join_thread(id) pthread_join(id, NULL)
#define destroy_thread(id)
#define THREAD_FUNC void *
#define THREAD_RETURN return NULL

#endif // if WINDOWS

#define VERSIONSTR "UFTP version 4.7  Copyright (C) 2001-2015  Dennis A. Bush"
#define UFTP_VER_NUM 0x40

#define ANNOUNCE      1
#define REGISTER      2
#define CLIENT_KEY    3
#define REG_CONF      4
#define KEYINFO       5
#define KEYINFO_ACK   6
#define FILEINFO      7
#define FILEINFO_ACK  8
#define FILESEG       9
#define DONE         10
#define STATUS       11
#define COMPLETE     12
#define DONE_CONF    13
#define HB_REQ       14
#define HB_RESP      15
#define KEY_REQ      16
#define PROXY_KEY    17
#define ENCRYPTED    18
#define ABORT        19 
#define CONG_CTRL    20
#define CC_ACK       21

#define FTYPE_REG       0
#define FTYPE_DIR       1
#define FTYPE_LINK      2
#define FTYPE_DELETE    3
#define FTYPE_FREESPACE 4

#define KEY_NONE        0
#define KEY_DES         1
#define KEY_DES_EDE3    2
#define KEY_AES128_CBC  3
#define KEY_AES256_CBC  4
#define KEY_AES128_GCM  5
#define KEY_AES256_GCM  6
#define KEY_AES128_CCM  7
#define KEY_AES256_CCM  8

#define HASH_NONE   0
#define HASH_MD5    1
#define HASH_SHA1   2
#define HASH_SHA256 3
#define HASH_SHA384 4
#define HASH_SHA512 5

#define SIG_NONE    0
#define SIG_HMAC    1
#define SIG_KEYEX   2
#define SIG_AUTHENC 3

#define KEYEX_NONE          0
#define KEYEX_RSA           1
#define KEYEX_ECDH_RSA      2
#define KEYEX_ECDH_ECDSA    3

#define KEYBLOB_RSA     1
#define KEYBLOB_EC      2

#define CURVE_sect163k1     1
#define CURVE_sect163r1     2
#define CURVE_sect163r2     3
#define CURVE_sect193r1     4
#define CURVE_sect193r2     5
#define CURVE_sect233k1     6
#define CURVE_sect233r1     7
#define CURVE_sect239k1     8
#define CURVE_sect283k1     9
#define CURVE_sect283r1     10
#define CURVE_sect409k1     11
#define CURVE_sect409r1     12
#define CURVE_sect571k1     13
#define CURVE_sect571r1     14
#define CURVE_secp160k1     15
#define CURVE_secp160r1     16
#define CURVE_secp160r2     17
#define CURVE_secp192k1     18
#define CURVE_secp192r1     19
#define CURVE_secp224k1     20
#define CURVE_secp224r1     21
#define CURVE_secp256k1     22
#define CURVE_secp256r1     23
#define CURVE_secp384r1     24
#define CURVE_secp521r1     25
#define CURVE_prime192v1    CURVE_secp192r1
#define CURVE_prime256v1    CURVE_secp256r1

#define CC_NONE     0
#define CC_UFTP3    1
#define CC_TFMCC    2
#define CC_PGMCC    3

#define EXT_ENC_INFO        1
#define EXT_TFMCC_DATA_INFO 2
#define EXT_TFMCC_ACK_INFO  3

#define EXT_PGMCC_DATA_INFO 4
#define EXT_PGMCC_NAK_INFO  5
#define EXT_PGMCC_ACK_INFO  6

#define EXT_FREESPACE_INFO 7

#define FLAG_SYNC_MODE      0x01
#define FLAG_SYNC_PREVIEW   0x02
#define FLAG_IPV6           0x04

#define FLAG_CLIENT_AUTH    0x01

#define FLAG_PARTIAL        0x01

#define FLAG_CURRENT_FILE   0x01

#define FLAG_CC_CLR         0x01
#define FLAG_CC_RTT         0x02
#define FLAG_CC_START       0x04
#define FLAG_CC_LEAVE       0x08

#define COMP_STAT_NORMAL    0
#define COMP_STAT_SKIPPED   1
#define COMP_STAT_OVERWRITE 2
#define COMP_STAT_REJECTED  3

#define HB_AUTH_FAILED      0
#define HB_AUTH_OK          1
#define HB_AUTH_CHALLENGE   2

#define MAXFILENAME 100
#define MAXDIRNAME 200
#define MAXPATHNAME 300
#define MAXBACKUPPATHNAME 600
#define MAXPROXYDEST 1000
#define MAXDIR 10
#define MAXSECTION 65536

#define DESTNAME_LEN 80
#define IFNAME_LEN 25
#define PORTNAME_LEN 20
#define MAX_INTERFACES 100
#define MAXMTU 9000

#define PUBKEY_LEN 264  // big enough for a keyblob with RSA-2048
#define RAND_LEN 32     // RFC 5246
#define HMAC_LEN 64     // big enough for SHA-512
#define VERIFY_LEN 12   // RFC 5246
#define MASTER_LEN 48   // RFC 5246
#define MAXIV 16        // big enough for AES256
#define MAXKEY 32       // big enough for AES256
#define KEYBLSIZE 16    // Maximum symmetric key blocksize
#define DEF_RSA_LEN 512 // Default length of generated RSA keys
#define DEF_CURVE CURVE_prime256v1  // Default EC curve
#define RSA_EXP 65537   // Public key exponent of generated RSA keys
#define SALT_LEN 4      // Length of salt for IV
#define GCM_IV_LEN 12   // Length of IV for ciphers in GCM mode
#define CCM_IV_LEN 12   // Length of IV for ciphers in CCM mode
#define GCM_TAG_LEN 16  // Length of tag for ciphers in GCM mode
#define CCM_TAG_LEN 16  // Length of tag for ciphers in CCM mode

#define ERR_NONE        0   // Normal exit code
#define ERR_PARAM       1   // One or more command line parameters invalid
#define ERR_SOCKET      2   // Error initializing sockets
#define ERR_CRYPTO      3   // Error initializing cryptographic keys
#define ERR_LOGGING     4   // Error while opening log file
#define ERR_ALLOC       5   // Memory allocation failure
#define ERR_INTERRUPTED 6   // Interrupted by the user or an unexpected signal
#define ERR_NO_REGISTER 7   // No client responded to ANNOUNCE with REGISTER
#define ERR_NO_FILEINFO 8   // No client responded to a FILEINFO
#define ERR_DROPPED     9   // All clients were lost or aborted
#define ERR_NO_FILES    10  // No files were sent

struct uftp_h {
    uint8_t version;
    uint8_t func;
    uint16_t seq;
    uint32_t src_id;        // ID of sender
    uint32_t group_id;
    uint8_t group_inst;     // Group restart number
    uint8_t grtt;           // RFC 5401, Unused in upstream messages
    uint8_t gsize;          // Unused in upstream messages
    uint8_t reserved;
};  // sizeof = 16

struct encrypted_h {
    uint32_t iv_ctr_hi;
    uint32_t iv_ctr_lo;
    uint16_t sig_len;
    uint16_t payload_len;
};  // sizeof = 12 + sig_len + payload_len

struct announce_h {
    uint8_t func;  // always ANNOUNCE
    uint8_t hlen;
    uint8_t flags;
    uint8_t robust;
    uint8_t cc_type;
    uint8_t reserved;
    uint16_t blocksize;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
    //uint32_t publicmcast;   // for IPv4
    //uint8_t publicmcast[16];  // for IPv6
    //uint32_t privatemcast;   // for IPv4
    //uint8_t privatemcast[16];  // for IPv6
};  // sizeof = 16 + 2*iplen + (encrypted?sizeof(enc_info_he):0) + {uint32_t[]}

struct enc_info_he {
    uint8_t exttype;   // always EXT_ENC_INFO
    uint8_t extlen;
    uint8_t flags;
    uint8_t keyextype_sigtype;  // & 0xF0 = keyextype, & 0x0F = sigtype
    uint8_t keytype;
    uint8_t hashtype;
    uint16_t keylen;
    uint16_t dhlen;
    uint16_t siglen;
    uint8_t rand1[RAND_LEN];
    //uint8_t keyblob[];
    //uint8_t dhkey[];
    //uint8_t sig[];
};  //sizeof = 44 + keylen + dhlen + siglen

struct rsa_blob_t {
    uint8_t blobtype;  // always KEYBLOB_RSA
    uint8_t reserved;
    uint16_t modlen;
    uint32_t exponent;
    //uint8_t modulus[];
};  //sizeof = 8 + modlen

struct ec_blob_t {
    uint8_t blobtype;  // always KEYBLOB_EC
    uint8_t curve;
    uint16_t keylen;
    //uint8_t key[];
};  //sizeof = 4 + keylen

struct client_key_h {
    uint8_t func;  // always CLIENT_KEY
    uint8_t hlen;
    uint16_t reserved;
    uint16_t bloblen;
    uint16_t siglen;
    //uint8_t keyblob[];
    //uint8_t verify[];
};  // sizeof = 8 + bloblen + siglen

struct register_h {
    uint8_t func;  // always REGISTER
    uint8_t hlen;
    uint16_t keyinfo_len;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
    uint8_t rand2[RAND_LEN];
    //uint8_t keyinfo[];  // Either an EC key or an RSA encrypted premaster
};  // sizeof = 44 + (server_key_len or ec_len) + {uint32_t[]}

struct regconf_h {
    uint8_t func;  // always REG_CONF
    uint8_t hlen;
    uint16_t reserved;
};  // sizeof = 4 + {uint32_t[]}

struct keyinfo_h {
    uint8_t func;  // always KEYINFO
    uint8_t hlen;
    uint16_t reserved;
    uint32_t iv_ctr_hi;
    uint32_t iv_ctr_lo;
};  // sizeof = 12 + {destkey[]}

struct destkey {
    uint32_t dest_id;
    uint8_t groupmaster[MASTER_LEN];      // based on 16 byte blocksize
};  // sizeof = 52 */

struct keyinfoack_h {
    uint8_t func;  // always KEYINFO_ACK
    uint8_t hlen;
    uint16_t reserved;
    uint8_t verify_data[VERIFY_LEN];
};  // sizeof = 16

struct fileinfo_h {
    uint8_t func;  // always FILEINFO
    uint8_t hlen;
    uint16_t file_id;
    uint8_t ftype;
    uint8_t reserved1;
    uint16_t reserved2;
    uint8_t namelen;
    uint8_t linklen;
    uint16_t hifsize;
    uint32_t lofsize;
    uint32_t ftstamp;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
    //char name[MAXPATHNAME];
};  // sizeof = 28 + namelen + {uint32_t[]}

struct fileinfoack_h {
    uint8_t func;  // always FILEINFO_ACK
    uint8_t hlen;
    uint16_t file_id;
    uint8_t flags;
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
};  // sizeof = 16 + {uint32_t[]}

struct fileseg_h {
    uint8_t func;  // always FILESEG
    uint8_t hlen;
    uint16_t file_id;
    uint16_t section;
    uint16_t sec_block;
};  // sizeof = 8 

// Append to FILESEG
struct tfmcc_data_info_he {
    uint8_t exttype;   // always EXT_TFMCC_DATA_INFO
    uint8_t extlen;
    uint16_t send_rate;
    uint16_t cc_seq;
    uint16_t cc_rate;
};  // sizeof = 8

// Append to FILESEG
struct pgmcc_data_info_he {
    uint8_t exttype;   // always EXT_PGMCC_DATA_INFO
    uint8_t extlen;
    uint16_t reserved;
    uint32_t acker;
};  // sizeof = 8

struct done_h {
    uint8_t func;  // always DONE
    uint8_t hlen;
    uint16_t file_id;
    uint16_t section;
    uint16_t reserved;
};  // sizeof = 8 + {uint32_t[]}

struct status_h {
    uint8_t func;  // always STATUS
    uint8_t hlen;
    uint16_t file_id;
    uint16_t section;
    uint16_t reserved;
};  // sizeof = 8 

// Append to STATUS or CC_ACK
struct tfmcc_ack_info_he {
    uint8_t exttype;   // always EXT_TFMCC_ACK_INFO
    uint8_t extlen;
    uint8_t flags;  // RTT, SS, LEAVE
    uint8_t reserved;
    uint16_t cc_seq;
    uint16_t cc_rate;
    uint32_t client_id;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
};  // sizeof = 20 

// Append to STATUS
struct pgmcc_nak_info_he {
    uint8_t exttype;   // always EXT_PGMCC_NAK_INFO
    uint8_t extlen;
    uint16_t loss;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
};  // sizeof = 12

// Append to CC_ACK
struct pgmcc_ack_info_he {
    uint8_t exttype;   // always EXT_PGMCC_ACK_INFO
    uint8_t extlen;
    uint16_t reserved;
    uint16_t loss;
    uint16_t max_seq;
    uint32_t ack_bitmap;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
};  // sizeof = 20

struct complete_h {
    uint8_t func;  // always COMPLETE
    uint8_t hlen;
    uint16_t file_id;
    uint8_t status;
    uint8_t reserved1;
    uint16_t reserved2;
};  // sizeof = 8 + {uint32_t[]}

struct freespace_info_he {
    uint8_t exttype;  // always EXT_FREESPACE_INFO
    uint8_t extlen;
    uint16_t reserved;
    uint32_t freespace_hi;
    uint32_t freespace_lo;
};  // sizeof = 12

struct doneconf_h {
    uint8_t func;  // always DONE_CONF
    uint8_t hlen;
    uint16_t reserved;
};  // sizeof = 4 + {uint32_t[]}

struct abort_h {
    uint8_t func;  // always ABORT
    uint8_t hlen;
    uint8_t flags;
    uint8_t reserved;
    uint32_t host;
    char message[300]; // TODO: define error codes
};  // sizeof = 308

struct hb_req_h {
    uint8_t func;  // always HB_REQ
    uint8_t hlen;
    uint16_t reserved;
    uint16_t bloblen;
    uint16_t siglen;
    uint32_t nonce;
    //uint8_t keyblob[];
    //uint8_t verify[];
};  // sizeof = 12 + bloblen + siglen

struct hb_resp_h {
    uint8_t func;  // always HB_RESP
    uint8_t hlen;
    uint8_t authenticated;
    uint8_t reserved;
    uint32_t nonce;
};  // sizeof = 8

struct key_req_h {
    uint8_t func;  // always KEY_REQ
    uint8_t hlen;
    uint16_t reserved;
};  // sizeof = 4

struct proxy_key_h {
    uint8_t func;  // always PROXY_KEY
    uint8_t hlen;
    uint16_t bloblen;
    uint16_t dhlen;
    uint16_t siglen;
    uint32_t nonce;
    //uint8_t keyblob[];
    //uint8_t dhkey[];
    //uint8_t verify[];
};  // sizeof = 12 + bloblen + dhlen + siglen

struct cong_ctrl_h {
    uint8_t func;  // always CONG_CTRL
    uint8_t hlen;
    uint16_t reserved;
    uint16_t cc_seq;
    uint16_t cc_rate;
    uint32_t tstamp_sec;
    uint32_t tstamp_usec;
}; // sizeof = 16 + {cc_item[]}

struct cc_item {
    uint32_t dest_id;
    uint8_t flags;  // CLR, RTT, START, LEAVE
    uint8_t rtt;    // RFC 5401
    uint16_t reserved;
}; // sizeof = 8

struct cc_ack_h {
    uint8_t func;  // always CC_ACK
    uint8_t hlen;
    uint16_t reserved;
}; // sizeof = 4 + tfmcc_info_he or pgmcc_info_ack_he

#endif  // _UFTP_H
