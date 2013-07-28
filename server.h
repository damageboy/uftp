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

#ifndef _SERVER_H
#define _SERVER_H

#include "uftp_common.h"
#include "encryption.h"

#define MAXDEST 100000
#define MAXFILES 10000
#define MAXEXCLUDE 500
#define MAXCC 20
#define CLIENT_RTT_MIN 0.001

/**
 * Values for deststate_t.status
 */ 
enum client_status {
    DEST_MUTE = -4,         /// Expected client that hasn't registered
    DEST_LOST = -3,         /// Client that timed out responding to a DONE
    DEST_ABORT = -2,        /// An ABORT was either sent to or received from
    DEST_REGISTERED = -1,   /// Registered but haven't received INFO_ACK
    DEST_ACTIVE = 0,        /// Ready to receive data
    DEST_DONE = 1           /// Client finished successfully, sent COMPLETE
};

/**
 * Destination state for a particular destination and file
 */
struct deststate_t {
    int conf_sent;          /// False if REG_CONF or DONE_CONF needs to be sent
    struct timeval time;    /// Time that this client finished
};

/**
 * File info struct
 */
struct finfo_t {
    int ftype;              /// File type (regular, directory, symlink)
    const char *basedir;    /// Base pathname of file in filesystem
    const char *filename;   /// Local name of file (may include path)
    const char *linkname;   /// For symbolic links, the text of the link
    const char *destfname;  /// Transmitted name of file (may include path)
    f_offset_t size;        /// File size in bytes
    int32_t tstamp;         /// Timestamp of file
    uint32_t blocks;        /// Total blocks in file
    uint16_t sections;      /// Total sections in file
    uint16_t big_sections;  /// Number of larger sized sections
    uint32_t secsize_small, secsize_big;  /// Size of sections
    uint32_t group_id;      /// Group ID
    uint8_t group_inst;     /// Group instance ID (restart number)
    uint16_t file_id;       /// File ID
    char *naklist;          /// Aggregate NAK list
    int partial;            /// True if all clients partially received last run
    struct deststate_t *deststate;  /// Status array for each client
};

/**
 * Encryption info for a particilar destination
 * Only allocated when encryption is enabled and only for proxies and clients
 * talking directly to the server.  Clients communicating through one or
 * more proxies maintain encryption state with the proxy, not the server.
 */
struct encinfo_t {
    union key_t pubkey;             /// The client's RSA or ECDSA public key
    int pubkeylen;                  /// The client's public key length in bytes
    union key_t dhkey;              /// The client's ECDH public key
    uint8_t verifydata[PUBKEY_LEN]; /// The verify data from a CLIENT_KEY
    uint16_t verifylen;             /// The length of verifydata in bytes
    uint8_t rand2[RAND_LEN];        /// Client's random number
    uint8_t premaster[MASTER_LEN];  /// Premaster secret sent by client
    int premaster_len;              /// Length of premaster secret
    uint8_t master[MASTER_LEN];     /// Master key for client
    uint8_t hmackey[HMAC_LEN];      /// HMAC key for client
    uint8_t key[MAXKEY];            /// Symmetric encryption key for client
    uint8_t salt[MAXIV];            /// Salt for block cypher IV for client
};

/**
 * Destination info
 */
struct destinfo_t {
    char name[DESTNAME_LEN];        /// Hostname of client
    uint32_t id;                    /// UID of client (network byte order)
    int proxyidx;                   /// Index of the proxy serving this client
    int clientcnt;                  /// The number of clients a proxy serves
    uint32_t *clients;              /// Indexes of clients served by this proxy
    int8_t status;                  /// Specified by a client_status value
    int8_t comp_status;             /// Completion status as given by COMPLETE
    int8_t registered;              /// True if we received a REGISTER
    int8_t verified;                /// True if we have a verified CLIENT_KEY
    int num_copy;                   /// Number of copied files in sync mode
    int num_skip;                   /// Number of skipped files in sync mode
    int num_overwrite;              /// Number of overwritten files in sync mode
    double total_time;              /// Total elasped sending time in sync mode
    f_offset_t total_size;          /// Total number of bytes sent in sync mode
    double rtt;                     /// RTT to this client
    int8_t rtt_measured;            /// True if RTT measured this round
    int8_t rtt_sent;                /// True if RTT sent in a CONG_CTRL
    int8_t has_fingerprint;         /// True if we have client's key fingerprint
    uint8_t keyfingerprint[HMAC_LEN];       /// Fingerprint of RSA key
    struct encinfo_t *encinfo;      /// If encryption enabled, encryption info
};

/**
 * Header of server restart file.
 * Followed in the file by filecount file names of MAXPATHNAME length,
 * followed by an arbitrary number of server_restart_host_t entries.
 */
struct server_restart_t {
    uint32_t group_id;              /// Group ID of failed transfer
    uint8_t group_inst;             /// Group instance ID of failed transfer
    int filecount;                  /// Number of files specified on cmdline
};

/**
 * Server restart file entry for a particular host.
 */
struct server_restart_host_t {
    char name[DESTNAME_LEN];        /// Hostname of client
    uint32_t id;                    /// UID of client (network byte order)
    int has_fingerprint;            /// True if we have client's key fingerprint
    uint8_t keyfingerprint[HMAC_LEN];       /// Fingerprint of RSA key
    int is_proxy;                   /// True if this is a proxy
};

/**
 * Congestion control configuration entrie.
 */
struct cc_config_t {
    double scaling_factor;          /// The given scaling factor
    int percentage;                 /// NAK percentage for the scaling factor
};

/**
 * Global command line values and sockets
 */
extern SOCKET sock;
extern union sockaddr_u listen_dest, receive_dest;
extern int max_rate, rate, rcvbuf, packet_wait;
extern int client_auth, quit_on_error, dscp, follow_links;
extern int save_fail, restart_groupid, restart_groupinst;
extern int sync_mode, sync_preview, dest_is_dir, cc_type;
extern unsigned int ttl;
extern char port[PORTNAME_LEN];
extern char pub_multi[INET6_ADDRSTRLEN], priv_multi[INET6_ADDRSTRLEN];
extern char logfile[MAXPATHNAME], keyfile[MAXPATHNAME], cc_config[MAXPATHNAME];
extern char filelist[MAXFILES][MAXPATHNAME], exclude[MAXEXCLUDE][MAXPATHNAME];
extern char basedir[MAXDIR][MAXDIRNAME], destfname[MAXPATHNAME];
extern struct iflist ifl[MAX_INTERFACES];
extern int keytype, hashtype, sigtype, keyextype, newkeylen, sys_keys;
extern int blocksize, datapacketsize;
extern int ifl_len, destcount, filecount, excludecount, basedircount, cc_count;
extern struct cc_config_t cc_list[MAXCC];
extern struct iflist out_if;
extern struct destinfo_t destlist[MAXDEST];

extern int robust;
extern double grtt, min_grtt, max_grtt;
extern uint16_t send_seq;
extern uint32_t server_id;

/**
 * Encryption variables
 */
extern union key_t privkey, dhkey;
extern unsigned char rand1[RAND_LEN], groupmaster[MASTER_LEN];
extern uint8_t groupsalt[MAXIV], groupkey[MAXKEY], grouphmackey[HMAC_LEN];
extern uint64_t ivctr;
extern int ivlen, keylen, hmaclen, privkeylen;
extern uint8_t ecdh_curve, ecdsa_curve;

/**
 * Variables shared between the sending and receiving threads
 * Defined in server_phase.c
 */
extern mux_t mux_main;

extern int rate_change;
extern uint32_t current_position;
extern uint32_t rewind_to;
extern uint16_t cc_seq;
extern uint32_t cc_rate;
extern double adv_grtt;

extern int slowstart, clr, clr_drop, new_rate;
extern struct timeval last_clr_time;

#endif  // _SERVER_H

