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

#ifndef _PROXY_H
#define _PROXY_H

#include "uftp_common.h"
#include "encryption.h"

#define MAX_PEND 10
#define MAXLIST 100
#define KEY_REQ_LIMIT 5

/**
 * Type of proxy
 */
enum proxy_type {
    UNDEF_PROXY = 0,            /// Not specified, indicates an error
    SERVER_PROXY = 1,           /// Server proxy: forwards to a specific place
    CLIENT_PROXY = 2,           /// Client proxy: sends to specified destaddr
    RESPONSE_PROXY = 3,         /// Response proxy: response aggregation only
};

/**
 * The state of the given group
 */
enum proxy_phase {
    PR_PHASE_REGISTERED = 1,    /// Currently setting up group
    PR_PHASE_READY = 2,         /// Still in setup, but received KEYINFO
    PR_PHASE_RECEIVING = 3,     /// Group setup complete
    PR_PHASE_DONE = 4,          /// All clients send COMPLETE for group
};

/**
 * The state of a given client when encryption is enabled
 */
enum proxy_client_state {
    PR_CLIENT_MUTE = 0,         /// Got nothing yet
    PR_CLIENT_REGISTERED = 1,   /// Got REGISTER (and CLIENT_KEY if required)
    PR_CLIENT_CONF = 2,         /// Got REG_CONF from server
    PR_CLIENT_READY = 3,        /// Got INFO_ACK in response to KEYINFO 
    PR_CLIENT_DONE = 4,         /// Sent COMPLETE for group
};

/**
 * Info for a particular client for the given group
 */
struct pr_destinfo_t {
    char name[DESTNAME_LEN];        /// Hostname of client
    uint32_t id;                    /// UID of client (network byte order)
    union key_t pubkey;             /// The client's public key
    int pubkeylen;                  /// The length of client's key in bytes
    union key_t dhkey;              /// The client's ECDH public key
    uint8_t verifydata[PUBKEY_LEN]; /// The verify data from a CLIENT_KEY
    uint16_t verifylen;             /// The length of verifydata in bytes
    int registered;                 /// True if we received a REGISTER
    struct timeval regtime;         /// Timestamp from last REGISTER
    int verified;                   /// True if we have a verified CLIENT_KEY
    int state;                      /// State as specified by proxy_client_state
    int pending;                    /// Index of pending message
    uint8_t rand2[RAND_LEN];        /// Client's random number
    uint8_t premaster[MASTER_LEN];  /// Premaster secret sent by client
    unsigned int premaster_len;     /// Length of premaster secret
    uint8_t master[MASTER_LEN];     /// Master key for client
    uint8_t hmackey[HMAC_LEN];      /// HMAC key for client
    uint8_t key[MAXKEY];            /// Symmetric encryption key for client
    uint8_t salt[MAXIV];            /// Salt for block cypher IV for client
};

/**
 * Info for a message pending to go upstream
 */
struct pr_pending_info_t {
    int msg, count;                 /// Type and number of pending responses
    uint16_t file_id;               /// File ID from last client message
    struct timeval tstamp;          /// Timestamp from last client message
    struct timeval rx_tstamp;       /// Time last client message received
    uint16_t section;               /// Section number from last status
    uint8_t *naklist;               /// NAK list from last status
    uint8_t partial;                /// PARTIAL flag from last FILEINFO_ACK
    uint8_t comp_status;            /// status flag from a COMPLETE
};

/**
 * Info for a particular group
 */
struct pr_group_list_t {
    uint32_t group_id;              /// Group ID
    uint8_t group_inst;             /// Group instance ID (restart number)
    uint16_t file_id;               /// Dummy field, present for logging macros
    uint8_t version;                /// Protocol version number of server
    uint32_t src_id;                /// ID of server
    double grtt;                    /// Server's GRTT
    uint8_t robust, cc_type;        /// Robust factor, congestion control type
    uint32_t gsize;                 /// Group size estimate
    int send_seq_up;                /// Outgoing upstream seq. number
    int send_seq_down;              /// Outgoing downstream seq. number
    union sockaddr_u publicmcast, privatemcast;
    int multi_join;                 /// True if we're listening on private addr
    unsigned int blocksize;         /// Size of packet payload
    unsigned int datapacketsize;    /// Max size of UFTP packet
    union sockaddr_u up_addr;       /// Upstream addr to send responses back to
    struct timeval phase_expire_time, phase_timeout_time, timeout_time;
    struct timeval start_phase_timeout_time, start_timeout_time;
    int phase, client_auth;
    int keyinfo_cnt;
    struct pr_pending_info_t pending[MAX_PEND];   /// Pending messages to send
    uint8_t last_seq;               /// Last sequence number used in STATUS
    int keytype, hashtype, sigtype, keyextype;   /// Encryption parameters
    union key_t server_pubkey;      /// Server's RSA public key
    union key_t proxy_privkey;      /// Proxy's RSA private key for this group
    union key_t server_dhkey;       /// Server ECDH public key for this group
    union key_t proxy_dhkey;        /// Proxy ECDH public key for this group
    unsigned int server_pubkeylen;  /// Length in bytes of server key
    unsigned int proxy_privkeylen;  /// Length in bytes of proxy key
    uint8_t rand1[RAND_LEN];        /// Server's random number
    uint8_t rand2[RAND_LEN];        /// Proxy's random number
    uint8_t premaster[MASTER_LEN];  /// Premaster secret sent by proxy
    unsigned int premaster_len;     /// Length of premaster secret
    uint8_t master[MASTER_LEN];     /// Master key for proxy
    uint8_t hmackey[HMAC_LEN];      /// HMAC key for proxy
    uint8_t key[MAXKEY];            /// Symmetric encryption key for proxy
    uint8_t salt[MAXIV];            /// Salt for block cypher IV for proxy
    uint8_t groupmaster[MASTER_LEN];/// Master key for server
    uint8_t grouphmackey[HMAC_LEN]; /// HMAC key for server
    uint8_t groupkey[MAXKEY];       /// Symmetric encryption key for server
    uint8_t groupsalt[MAXIV];       /// Salt for block cypher IV for server
    uint64_t ivctr;                 /// Counter portion of the IV
    int ivlen, keylen, hmaclen;     /// Length of HMAC key, symmetric key and iv
    struct pr_destinfo_t destinfo[MAXPROXYDEST];    /// List of clients
    int destcount;                  /// Number of clients served by this proxy
};

/**
 * Global command line values and sockets
 */
extern SOCKET listener;
extern char pidfile[MAXPATHNAME];
extern char keyfile[MAXLIST][MAXPATHNAME], keyinfo[MAXLIST][MAXPATHNAME];
extern int proxy_type, debug, rcvbuf, dscp, keyfile_count, keyinfo_count;
extern int hb_interval, priority;
extern unsigned int ttl;
char portname[PORTNAME_LEN], out_portname[PORTNAME_LEN];
int port, out_port;
extern union sockaddr_u down_addr;
extern int have_down_fingerprint;
extern uint8_t down_fingerprint[HMAC_LEN];
extern uint32_t down_nonce, uid;
extern union sockaddr_u hb_hosts[MAXLIST];
extern union sockaddr_u pub_multi[MAX_INTERFACES];
extern struct fp_list_t server_fp[MAXLIST], client_fp[MAXPROXYDEST];
extern struct iflist ifl[MAX_INTERFACES], m_interface[MAX_INTERFACES];
extern struct timeval next_hb_time, last_key_req;
extern int ifl_len, hbhost_count, server_fp_count, client_fp_count;
extern int key_count, pub_multi_count, interface_count, sys_keys;
extern struct iflist out_if;
extern union key_t privkey[MAXLIST];
extern int privkey_type[MAXLIST];
extern union key_t dhkey;
extern uint8_t ecdh_curve;
extern struct pr_group_list_t group_list[MAXLIST];

#endif  // _PROXY_H

