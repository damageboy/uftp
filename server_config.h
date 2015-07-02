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

#ifndef _SERVER_CONFIG_H
#define _SERVER_CONFIG_H

/**
 * Default command line values
 */
#define DEF_RATE                128000
#define DEF_PORT                "1044"
#define DEF_SRCPORT             "0"
#define DEF_PUB_MULTI           "230.4.4.1"
#define DEF_PRIV_MULTI          "230.5.5.x"
#define DEF_TTL                 1
#define DEF_DSCP                0
#define DEF_RCVBUF              262144
#define DEF_BSD_RCVBUF          233016
#define DEF_BLOCKSIZE           1300
#define DEF_GRTT                0.5
#define DEF_MIN_GRTT            0.01
#define DEF_MAX_GRTT            15.0
#define DEF_ROBUST              20
#define DEF_TXWEIGHT            0
#define DEF_MAX_NAK_PCT         100
#define DEF_MAX_NAK_CNT         1
#define DEF_KEYEXTYPE           KEYEX_RSA
#define DEF_KEYTYPE             KEY_NONE
#define DEF_HASHTYPE            HASH_SHA1
#define DEF_SIGTYPE             SIG_HMAC

#define USAGE \
"Usage: uftp [OPTION] file...\n\
  Transfer files using the UFTP protocol\n\
   -R, --rate=TXRATE                                 transmission speed in Kbps\n\
   -L, --log-file logfile                            the log file, defaults to stderr\n\
   -B, --buffer-size=SIZE                            the UDP send/receive buffer size\n\
   -Y, --key-type=KEYTYPE                            the symmetric encryption algorithm to use\n\
   -h, --hash-type=HASHTYPE                          the hashing algorithm to use\n\
   -w, --sig-type=SIGTYPE                            the signature type to apply to encrypted messages\n\
   -e, --key-exch-type=KEYEXTYPE[:CURVE]             the key-exchange algorithm to use\n\
   -c, --force-public-key                            for client to authenticate with public key\n\
   -k, --key-file=KEYFILE                            the key file to use\n\
   -K, --key-length new_key_length | curve           set the servers RSA/ECDSA key length\n\
   -l, --follow-symlinks                             follow symbolic links\n\
   -T, --timestamp                                   print timestamps on each output line\n\
   -b, --block-size block_size                       specify the size of a data block\n\
   -t, --ttl=TTL                                     time-to-live for multicast packets\n\
   -Q, --dscp=DSCP                                   specifies the Differentiated Services Code Point\n\
   -z,  --sync                                       sync mode; Clients will check if an \n\
                                                     incoming file exists, skip when unchabged\n\
   -Z, --sync-preview                                sync preview mode; same as sync mode\n\
                                                     but no files actually transmitted\n\
   -I, --interface=IFACE                             interface to send data from\n\
   -U, --uid=UID                                     The unique ID for this client, as 0xnnnnnnnn\n\
   -p, --dest-port=PORT                              UDP port # to send to\n\
   -g, --src-port=PORT                               UDP source port # to attempt to bind to\n\
   -j, --proxy-list=FILE                             specifies a file containing a list of proxies\n\
                                                     the server is expecting to hear from\n\
   -q, --quit-on-error                               quit on error\n\
   -f, --restartable                                 restartable mode\n\
   -y, --use-system-crypto                           use windows system crypto store\n\
   -x, --log-level=LEVEL                             set the log level\n\
   -H, --host { host[,host...] | @hostlist_file }    specify a list of clients either as comma-\n\
                                                     separated hosts or from a text file\n\
   -F, --restart-file=FILE                           specifies the name of a restart file to use\n\
                                                     to resume a failed transfer\n\
   -X, --exclude-file=FILE                           A file containing the names of files/paths\n\
                                                     to be excluded from the session, one per line\n\
   -M, --public-mcast=ADDRESS                        the  public  address  to announce on.\n\
                                                     May be either a multicast or a unicast address\n\
   -P, --private-mcast=ADDRESS                       the private multicast address that the \n\
                                                     data is transferred to\n\
   -C, --congestion-control=CCTYPE                   specifies the congestion control mode to	use\n\
                                                     see the man page for more details and examples\n\
   -o, --dest-is-directory                           treat destination as directory\n\
   -D, --dest-name=NAME                              these options specify the name given to\n\
                                                     the sent file(s) on the client side\n\
   -E, --base-dir=DIR1[,DIR2...]                     specifies one or more \"base\" directories for files\n\
   -r, --grtt=init_grtt[:min_grtt:max_grtt]          provide GRTT parameters \n\
   -s, --robust=VALUE                                specifies the robustness factor for message retransmission\n\
   -i, --file-list=FILE                              name of a file containing a list of files\n\
                                                     to send, one per line\n"

void process_args(int argc, char *argv[]);

#endif  // _SERVER_CONFIG_H

