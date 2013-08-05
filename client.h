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

#ifndef _CLIENT_H
#define _CLIENT_H

#include "uftp_common.h"
#include "encryption.h"

#define MAXLIST 100
#define MAXMISORDER 5
#define KEY_REQ_INT 5

/**
 * Current state of client for a given group
 */
enum client_phase {
    PHASE_REGISTERED = 1,       /// Registered and awaiting KEYINFO or REG_CONF
    PHASE_RECEIVING = 2,        /// Currently receiving a file
    PHASE_COMPLETE = 3,         /// Completed group and awaiting DONE_CONF
    PHASE_MIDGROUP = 4          /// Registered awaiting next file or group end
};

/**
 * Info pertaining to current file
 */
struct file_t {
    uint32_t blocks;            /// Total blocks
    uint16_t sections;          /// Total sections
    uint16_t big_sections;      /// Number of larger sized sections
    uint32_t secsize_small, secsize_big;  /// Size of sections
    int ftype;                  /// File type (regular, directory, symlink)
    f_offset_t size;            /// Size in bytes
    int32_t tstamp;             /// File timestamp
    char filepath[MAXPATHNAME]; /// Local path to file
    char temppath[MAXPATHNAME]; /// Local path to temp file
    char name[MAXPATHNAME];     /// Path name
    char linkname[MAXPATHNAME]; /// Link name (symlinks only)
    uint8_t *naklist;           /// NAK list
    uint8_t *section_done;      /// Array of done flags for each section
    int fd;                     /// File descriptor for file
    uint32_t last_block;        /// Block number of last block received
    uint16_t last_section;      /// Section number of last block received
    struct timeval nak_time;    /// Time to send out NAKs
    uint16_t nak_section_first; /// First section number to send NAKs for
    uint16_t nak_section_last;  /// Last section number to send NAKs for
    int got_done;               /// A DONE was received for this client
    f_offset_t curr_offset;     /// Current file pointer offset in fd
    int restart;                /// True if restarting a prior session
    int comp_status;            /// Value for status field of COMPLETE
    int destdiridx;             /// Index of dest dir file is received in
};

/**
 * Header of client save state file.
 * Followed in the file by the NAK list and section_done list.
 * The naklist and section_done fields are left blank when the struct is
 * written to a file.  When read back in, memory is allocated and the
 * NAK list and section_done list are written to them.
 */
struct client_restart_t {
    uint32_t blocks;            /// Total blocks
    uint32_t sections;          /// Total sections
    f_offset_t size;            /// Size in bytes
    char name[MAXPATHNAME];     /// Path name
    uint8_t *naklist;           /// NAK list
    uint8_t *section_done;      /// Array of done flags for each section
};

/**
 * Loss history item.
 * These are part of an array where the array index is the sequence number.
 */
struct loss_history_t {
    int found;                  /// True if this packet was received
    struct timeval t;           /// Time received, either actual or inferred
    int size;                   /// Size of received packet, including UDP/IP
};

/**
 * Loss event item.
 */
struct loss_event_t {
    uint32_t start_seq;         /// Seq num of event start, including wraparound
    int len;                    /// Size of loss interval
    struct timeval t;           /// Timestamp of event start
};

/**
 * Info for a particular group
 */
struct group_list_t {
    uint32_t group_id;              /// Group ID
    uint8_t group_inst;             /// Group instance ID (restart number)
    uint16_t file_id;               /// File ID of current file
    uint8_t version;                /// Protocol version number of server
    union sockaddr_u multi;         /// Private multicast address
    int multi_join;                 /// True if we're listening on private addr
    char start_date[10];            /// Date initial ANNOUNCE was received
    char start_time[10];            /// Time initial ANNOUNCE was received
    uint16_t send_seq;              /// Outgoing seq. number for loss detection
    uint32_t src_id;                /// ID of server (network byte order)
    union sockaddr_u replyaddr;
    int phase;                      /// Current client_phase of the group
    int client_auth, restart, sync_mode, sync_preview; /// Flags from ANNOUNCE
    struct client_restart_t *restartinfo; /// Restart file header
    unsigned int blocksize;         /// Size of packet payload
    unsigned int datapacketsize;    /// Max size of UFTP packet
    struct timeval timeout_time, start_timeout_time, expire_time;
    double rtt, grtt;               /// Client's RTT and server's GRTT
    uint16_t start_txseq, max_txseq;  /// Server's starting, max sequence #
    struct loss_history_t *loss_history;  /// Loss history
    struct loss_event_t loss_events[9];   /// Loss event history
    int seq_wrap;                   /// Number of times server seq wrapped
    int ccseq;                      /// Current congestion control sequence #
    uint32_t initrate;              /// Cong. control rate at start of fb round
    int isclr;                      /// True if this client is the CLR
    int slowstart;                  /// True if we're in slowstart mode
    uint8_t robust, cc_type;        /// Robust factor, congestion control type
    uint32_t gsize;                 /// Group size estimate
    struct timeval cc_time;         /// Timer for sending CC_ACK
    struct timeval last_server_ts, last_server_rx_ts;
    int keytype, hashtype, sigtype, keyextype;   /// Encryption parameters
    union key_t server_pubkey;      /// Server's public key
    union key_t client_privkey;     /// Client's private key for this group
    union key_t server_dhkey;       /// Server ECDH public key for this group
    union key_t client_dhkey;       /// Client ECDH public key for this group
    unsigned int server_pubkeylen;  /// Length in bytes of server key
    unsigned int client_privkeylen; /// Length in bytes of client key
    uint8_t rand1[RAND_LEN];        /// Server's random number
    uint8_t rand2[RAND_LEN];        /// Client's random number
    uint8_t premaster[MASTER_LEN];  /// Premaster secret sent by client
    unsigned int premaster_len;     /// Length of premaster secret
    uint8_t master[MASTER_LEN];     /// Master key for client
    uint8_t hmackey[HMAC_LEN];      /// HMAC key for client
    uint8_t key[MAXKEY];            /// Symmetric encryption key for client
    uint8_t salt[MAXIV];            /// Salt for block cypher IV for client
    uint8_t groupmaster[MASTER_LEN];/// Master key for server
    uint8_t grouphmackey[HMAC_LEN]; /// HMAC key for server
    uint8_t groupkey[MAXKEY];       /// Symmetric encryption key for server
    uint8_t groupsalt[MAXIV];       /// Salt for block cypher IV for server
    uint64_t ivctr;                 /// Counter portion of the IV
    int ivlen, keylen, hmaclen;     /// Length of HMAC key, symmetric key and iv
    struct file_t fileinfo;         /// Info pertaining to current file
};

/**
 * Global command line values and sockets
 */
extern SOCKET listener;
extern char tempdir[MAXDIRNAME], destdir[MAXDIR][MAXDIRNAME];
extern char pidfile[MAXPATHNAME];
extern char keyfile[MAXLIST][MAXPATHNAME], keyinfo[MAXLIST][MAXPATHNAME];
extern char backupdir[MAXDIR][MAXDIRNAME];
extern int debug, encrypted_only, dscp, destdircnt, tempfile, keyinfo_count;
extern int interface_count, pub_multi_count, keyfile_count, rcvbuf, backupcnt;
extern char postreceive[MAXPATHNAME], portname[PORTNAME_LEN];
extern int port, move_individual;
extern uint32_t uid;
extern union sockaddr_u hb_hosts[MAXLIST];
extern struct iflist m_interface[MAX_INTERFACES];
extern union sockaddr_u pub_multi[MAX_INTERFACES];
extern struct group_list_t group_list[MAXLIST];
extern struct fp_list_t server_keys[MAXLIST];
extern struct iflist ifl[MAX_INTERFACES];
extern struct timeval next_keyreq_time, next_hb_time;
extern int ifl_len, server_count, key_count, has_proxy, sys_keys, priority;
extern int hbhost_count, hb_interval;
extern union key_t privkey[MAXLIST];
extern int privkey_type[MAXLIST];
extern struct fp_list_t proxy_info;
extern union key_t proxy_pubkey, proxy_dhkey;
extern int proxy_pubkeytype;

#endif  // _CLIENT_H

