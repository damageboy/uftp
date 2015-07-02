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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WINDOWS

#include <io.h>
#include "win_func.h"

#else  // if WINDOWS

#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#endif

#include "server.h"
#include "server_config.h"

/**
 * Global command line values and sockets
 */
SOCKET sock;
union sockaddr_u listen_dest, receive_dest;
int max_rate, rate, rcvbuf, packet_wait, txweight, max_nak_pct;
int client_auth, quit_on_error, dscp, follow_links, max_nak_cnt;
int save_fail, restart_groupid, restart_groupinst, files_sent; 
int sync_mode, sync_preview, dest_is_dir, cc_type, user_abort;
unsigned int ttl;
char port[PORTNAME_LEN], srcport[PORTNAME_LEN];
char pub_multi[INET6_ADDRSTRLEN], priv_multi[INET6_ADDRSTRLEN]; 
char keyfile[MAXPATHNAME];
char filelist[MAXFILES][MAXPATHNAME], exclude[MAXEXCLUDE][MAXPATHNAME];
char basedir[MAXDIR][MAXDIRNAME], destfname[MAXPATHNAME];
char statusfilename[MAXPATHNAME];
FILE *status_file;
struct iflist ifl[MAX_INTERFACES];
int keytype, hashtype, sigtype, keyextype, newkeylen, sys_keys;
int blocksize, datapacketsize;
int ifl_len, destcount, filecount, excludecount, basedircount;
struct iflist out_if;
struct destinfo_t destlist[MAXDEST];

int robust;
double grtt, min_grtt, max_grtt;
uint16_t send_seq;
uint32_t server_id;

/**
 * Encryption variables
 */
union key_t privkey, dhkey;
unsigned char rand1[RAND_LEN], groupmaster[MASTER_LEN];
uint8_t groupsalt[MAXIV], groupkey[MAXKEY], grouphmackey[HMAC_LEN];
uint64_t ivctr;
int ivlen, keylen, hmaclen, privkeylen;
uint8_t ecdh_curve, ecdsa_curve;


/**
 * Add a destination or proxy to the list as specified by -H or -j
 */
void add_dest_by_name(const char *destname, const char *fingerprint, int proxy)
{
    struct addrinfo ai_hints, *ai_rval;
    uint32_t uid;
    int rval;

    if (destcount == MAXDEST) {
        fprintf(stderr,"Exceeded maximum destination count\n");
        exit(ERR_PARAM);
    }

    // Check if the client is specified by an IPv4 name/address
    ai_hints.ai_family = AF_INET;
    ai_hints.ai_socktype = SOCK_DGRAM;
    ai_hints.ai_protocol = 0;
    ai_hints.ai_flags = 0;
    if ((rval = getaddrinfo(destname, NULL, &ai_hints, &ai_rval)) != 0) {
        uid = strtoul(destname, NULL, 16);
        if ((uid == 0xffffffff) || (uid == 0)) {
            fprintf(stderr, "Invalid UID %s\n", destname);
            exit(ERR_PARAM);
        }
        destlist[destcount].id = htonl(uid);
    } else {
        destlist[destcount].id =
               ((struct sockaddr_in *)ai_rval->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(ai_rval);
    }

    snprintf(destlist[destcount].name, sizeof(destlist[destcount].name),
             "%s", destname);
    destlist[destcount].proxyidx = -1;
    destlist[destcount].clientcnt = proxy ? 0 : -1;
    destlist[destcount].has_fingerprint =
            parse_fingerprint(destlist[destcount].keyfingerprint, fingerprint);
    destcount++;
}

/**
 * Set defaults for all command line arguments
 */
void set_defaults(void)
{
    memset(destlist, 0, sizeof(destlist));
    memset(filelist, 0, sizeof(filelist));
    memset(exclude, 0, sizeof(exclude));
    memset(destfname, 0, sizeof(destfname));
    destcount = 0;
    strncpy(port, DEF_PORT, sizeof(port)-1);
    port[sizeof(port)-1] = '\x0';
    strncpy(srcport, DEF_SRCPORT, sizeof(srcport)-1);
    srcport[sizeof(srcport)-1] = '\x0';
    rate = DEF_RATE;
    max_rate = 0;
    memset(&out_if, 0, sizeof(out_if));
    ttl = DEF_TTL;
    dscp = DEF_DSCP;
    blocksize = DEF_BLOCKSIZE;
    log_level = DEF_LOG_LEVEL;
    rcvbuf = 0;
    memset(keyfile, 0, sizeof(keyfile));
    client_auth = 0;
    quit_on_error = 0;
    save_fail = 0;
    server_id = 0;
    files_sent = 0;
    restart_groupid = 0;
    restart_groupinst = 0;
    keytype = DEF_KEYTYPE;
    hashtype = DEF_HASHTYPE;
    sigtype = DEF_SIGTYPE;
    keyextype = DEF_KEYEXTYPE;
    ecdh_curve = DEF_CURVE;
    strncpy(pub_multi, DEF_PUB_MULTI, sizeof(pub_multi)-1);
    pub_multi[sizeof(pub_multi)-1] = '\x0';
    strncpy(priv_multi, DEF_PRIV_MULTI, sizeof(priv_multi)-1);
    priv_multi[sizeof(priv_multi)-1] = '\x0';
    strncpy(logfile, "", sizeof(logfile)-1);
    logfile[sizeof(logfile)-1] = '\x0';
    strncpy(statusfilename, "", sizeof(statusfilename)-1);
    statusfilename[sizeof(statusfilename)-1] = '\x0';
    status_file = NULL;
    filecount = 0;
    excludecount = 0;
    basedircount = 0;
    newkeylen = 0;
    ecdh_curve = 0;
    ecdsa_curve = 0;
    follow_links = 0;
    showtime = 0;
    sys_keys = 0;
    sync_mode = 0;
    sync_preview = 0;
    dest_is_dir = 0;
    grtt = DEF_GRTT;
    min_grtt = DEF_MIN_GRTT;
    max_grtt = DEF_MAX_GRTT;
    robust = DEF_ROBUST;
    send_seq = 0;
    user_abort = 0;
    txweight = DEF_TXWEIGHT;
    max_nak_pct = DEF_MAX_NAK_PCT;
    max_nak_cnt = DEF_MAX_NAK_CNT;
    max_log_size = 0;
    max_log_count = DEF_MAX_LOG_COUNT;
}

/**
 * Reads in the contents of the restart file.
 * Contains a server_restart_t header, followed by
 * one or more server_restart_host_t entries.
 */
void read_restart_file(const char *restart_name)
{
    struct server_restart_t header;
    struct server_restart_host_t host;
    int fd, i, rval;

    if ((fd = open(restart_name, OPENREAD)) == -1) {
        syserror(0, 0, "Failed to open restart file");
        exit(ERR_PARAM);
    }

    if (file_read(fd, &header, sizeof(header), 0) == -1) {
        log0(0, 0, "Failed to read header from restart file");
        close(fd);
        exit(ERR_PARAM);
    }
    restart_groupid = header.group_id;
    restart_groupinst = header.group_inst;

    if (restart_groupinst == 0xff) {
        log0(0, 0, "Maximum number of restarts reached");
        close(fd);
        exit(ERR_PARAM);
    }
    if ((header.filecount > MAXFILES) || (header.filecount <= 0)) {
        log0(0, 0, "Too many files listed in restart file");
        close(fd);
        exit(ERR_PARAM);
    }
    for (i = 0; i < header.filecount; i++) {
        if (file_read(fd, filelist[i], sizeof(filelist[i]), 0) == -1) {
            log0(0, 0, "Failed to read filename from restart file");
            close(fd);
            exit(ERR_PARAM);
        }
    }
    filecount = header.filecount;

    while ((rval = file_read(fd, &host, sizeof(host), 1)) != 0) {
        if (rval == -1) {
            log0(0, 0, "Failed to read host from restart file");
            close(fd);
            exit(ERR_PARAM);
        }
        memcpy(destlist[destcount].name, host.name, sizeof(host.name));
        destlist[destcount].id = host.id;
        destlist[destcount].proxyidx = -1;
        destlist[destcount].clientcnt = host.is_proxy ? 0 : -1;
        destlist[destcount].has_fingerprint = host.has_fingerprint;
        if (host.has_fingerprint) {
            memcpy(destlist[destcount].keyfingerprint, host.keyfingerprint,
                   sizeof(destlist[destcount].keyfingerprint));
        }
        destcount++;
    }
    close(fd);
}

/**
 * Gets the symmetric cypher constant for the given cypher name
 * Returns -1 if the name is invalid
 */
static int get_keytype(const char *name)
{
    if (!strcmp(optarg, "none")) {
        return KEY_NONE;
    } else if (!strcmp(optarg, "des")) {
        return KEY_DES;
    } else if (!strcmp(optarg, "3des")) {
        return KEY_DES_EDE3;
    } else if (!strcmp(optarg, "aes128-cbc")) {
        return KEY_AES128_CBC;
    } else if (!strcmp(optarg, "aes256-cbc")) {
        return KEY_AES256_CBC;
    } else if (!strcmp(optarg, "aes128-gcm")) {
        return KEY_AES128_GCM;
    } else if (!strcmp(optarg, "aes256-gcm")) {
        return KEY_AES256_GCM;
    } else if (!strcmp(optarg, "aes128-ccm")) {
        return KEY_AES128_CCM;
    } else if (!strcmp(optarg, "aes256-ccm")) {
        return KEY_AES256_CCM;
    } else {
        return -1;
    }
}

/**
 * Gets the hash constant for the given hash name
 * Returns -1 if the name is invalid
 */
static int get_hashtype(const char *name)
{
    if (!strcmp(optarg, "sha1")) {
        return HASH_SHA1;
    } else if (!strcmp(optarg, "sha256")) {
        return HASH_SHA256;
    } else if (!strcmp(optarg, "sha384")) {
        return HASH_SHA384;
    } else if (!strcmp(optarg, "sha512")) {
        return HASH_SHA512;
    } else {
        return -1;
    }
}

/**
 * Set argument defaults, read and validate command line options
 */
void process_args(int argc, char *argv[])
{
    int c, i, listidx, read_restart, rval, longidx;
    long tmpval;
    char line[1000], *dest, *destname, filename[MAXPATHNAME], *fingerprint, *p;
    char keylenstr[50];
    struct addrinfo ai_hints, *ai_rval;
    FILE *destfile, *excludefile, *listfile;
    const char opts[] = "x:R:L:B:g:n:m:Y:h:w:e:ck:K:lTb:t:Q:"
                        "zZI:p:u:j:qfyU:H:F:X:M:P:C:D:oE:S:r:s:i:W:N:";

    const struct option long_opts[] = {
        { "rate", required_argument, NULL, 'R' },
        { "log-level", required_argument, NULL, 'x' },
        { "log-file", required_argument, NULL, 'L' },
        { "buffer-size", required_argument, NULL, 'B' },
        { "key-type", required_argument, NULL, 'Y' },
        { "hash-type", required_argument, NULL, 'h' },
        { "sig-type", required_argument, NULL, 'w' },
        { "key-exch-type", required_argument, NULL, 'e' },
        { "force-public-key", no_argument, NULL, 'c' },
        { "key-file", required_argument, NULL, 'k' },
        { "key-length", required_argument, NULL, 'K' },        
        { "follow-symlinks", no_argument, NULL, 'l' },
        { "timestamp", no_argument, NULL, 'T' },
        { "block-size", required_argument, NULL, 'b' },
        { "ttl", required_argument, NULL, 't' },
        { "dscp", required_argument, NULL, 'Q' },
        { "interface", required_argument, NULL, 'I' },
        { "sync", no_argument, NULL, 'z' },
        { "sync-preview", no_argument, NULL, 'Z' },
        { "dest-port", required_argument, NULL, 'p' },
        { "src-port", required_argument, NULL, 'g' },
        { "proxy-list", required_argument, NULL, 'j' },
        { "quit-on-error", no_argument, NULL, 'q' },
        { "restartable", no_argument, NULL, 'f' },
        { "use-system-crypto", no_argument, NULL, 'y' },
        { "host", required_argument, NULL, 'H' },
        { "restart-file", required_argument, NULL, 'F' },
        { "exclude-file", required_argument, NULL, 'X' },
        { "public-mcast", required_argument, NULL, 'M' },
        { "private-mcast", required_argument, NULL, 'P' },
        { "congestion-control", required_argument, NULL, 'C' },
        { "dest-name", required_argument, NULL, 'D' },
        { "dest-is-directory", no_argument, NULL, 'o' },
        { "base-dir", required_argument, NULL, 'E' },
        { "grtt", required_argument, NULL, 'r' },
        { "robust", required_argument, NULL, 's' },
        { "file-list", required_argument, NULL, 'i' },
		{ "uid", required_argument, NULL, 'U' },
        { "help", required_argument, NULL, '?' }
    };


    set_defaults();
    memset(keylenstr, 0, sizeof(keylenstr));
    read_restart = 0;

    // read lettered arguments
    while ((c = getopt_long(argc, argv, opts, long_opts, &longidx)) != EOF) {
        switch (c) {
        case 'x':
            log_level = atoi(optarg);
            if (log_level < 0) {
                fprintf(stderr,"Invalid log level\n");
                exit(ERR_PARAM);
            }
            break;
        case 'R':
            // Expecting rate as Kbps, translate to B/s
            rate = atoi(optarg);
            if ((rate <= 0) && (rate != -1)) {
                fprintf(stderr,"Invalid rate\n");
                exit(ERR_PARAM);
            }
            if (rate != -1) {
                rate = rate * 1024 / 8;
            }
            break;
        case 'L':
            strncpy(logfile, optarg, sizeof(logfile)-1);
            logfile[sizeof(logfile)-1] = '\x0';
            break;
        case 'B':
            rcvbuf = atoi(optarg);
            if ((rcvbuf < 65536) || (rcvbuf > 104857600)) {
                fprintf(stderr, "Invalid receive buffer size\n");
                exit(ERR_PARAM);
            }
            break;
        case 'g':
            max_log_size = atoi(optarg);
            if ((max_log_size < 1) || (max_log_size > 1024)) {
                fprintf(stderr, "Invalid max log size\n");
                exit(ERR_PARAM);
            }
            max_log_size *= 1000000;
            break;
        case 'n':
            max_log_count = atoi(optarg);
            if ((max_log_count < 1) || (max_log_count > 1000)) {
                fprintf(stderr, "Invalid max log count\n");
                exit(ERR_PARAM);
            }
            break;
        case 'm':
            max_nak_cnt = atoi(optarg);
            if ((max_nak_cnt < 1) || (max_nak_cnt > 1000)) {
                fprintf(stderr, "Invalid max nak count\n");
                exit(ERR_PARAM);
            }
            break;
        case 'Y':
            if ((keytype = get_keytype(optarg)) == -1) {
                fprintf(stderr, "Invalid keytype\n");
                exit(ERR_PARAM);
            }
            if (keytype != KEY_NONE && !cipher_supported(keytype)) {
                fprintf(stderr, "Keytype not supported\n");
                exit(ERR_PARAM);
            }
            break;
        case 'h':
            if ((hashtype = get_hashtype(optarg)) == -1) {
                fprintf(stderr, "Invalid hashtype\n");
                exit(ERR_PARAM);
            }
            if (!hash_supported(hashtype)) {
                fprintf(stderr, "Hashtype not supported\n");
                exit(ERR_PARAM);
            }
            break;
        case 'w':
            if (!strcmp(optarg, "hmac")) {
                sigtype = SIG_HMAC;
            } else if (!strcmp(optarg, "keyex")) {
                sigtype = SIG_KEYEX;
            } else {
                fprintf(stderr, "Invalid sigtype\n");
                exit(ERR_PARAM);
            }
            break;
        case 'e':
            p = strtok(optarg, ":");
            if (!p) {
                fprintf(stderr, "Error reading keyextype\n");
                exit(ERR_PARAM);
            }
            if (!strcmp(p, "rsa")) {
                keyextype = KEYEX_RSA;
            } else if (!strcmp(p, "ecdh_rsa")) {
                keyextype = KEYEX_ECDH_RSA;
            } else if (!strcmp(p, "ecdh_ecdsa")) {
                keyextype = KEYEX_ECDH_ECDSA;
            } else {
                fprintf(stderr, "Invalid keyextype\n");
                exit(ERR_PARAM);
            }
            if ((keyextype == KEYEX_ECDH_RSA) ||
                    (keyextype == KEYEX_ECDH_ECDSA)) {
                p = strtok(NULL, ":");
                if (p) {
                    ecdh_curve = get_curve(p);
                    if (ecdh_curve == 0) {
                        fprintf(stderr, "Invalid curve\n");
                        exit(ERR_PARAM);
                    }
                } else {
                    ecdh_curve = DEF_CURVE;
                }
            }
            break;
        case 'c':
            client_auth = 1;
            break;
        case 'k':
            strncpy(keyfile, optarg, sizeof(keyfile)-1);
            keyfile[sizeof(keyfile)-1] = '\x0';
            break;
        case 'K':
            strncpy(keylenstr, optarg, sizeof(keylenstr)-1);
            keylenstr[sizeof(keylenstr)-1] = '\x0';
            break;
        case 'l':
            follow_links = 1;
            break;
        case 'T':
            showtime = 1;
            break;
        case 'b':
            blocksize = atoi(optarg); 
            if ((blocksize < 512) || (blocksize > (MAXMTU - 200))) {
                fprintf(stderr, "Invalid blocksize\n");
                exit(ERR_PARAM);
            }
            break;
        case 't':
            tmpval = atoi(optarg);
            if ((tmpval <= 0) || (tmpval > 255)) {
                fprintf(stderr, "Invalid ttl\n");
                exit(ERR_PARAM);
            }
            ttl = (char)tmpval;
            break;
        case 'Q':
            tmpval = strtol(optarg, NULL, 0);
            if ((tmpval < 0) || (tmpval > 63)) {
                fprintf(stderr, "Invalid dscp\n");
                exit(ERR_PARAM);
            }
            dscp = (tmpval & 0xFF) << 2; 
            break;
        case 'I':
            if ((listidx = getifbyname(optarg, ifl, ifl_len)) != -1) {
                out_if = ifl[listidx];
                break;
            }
            memset(&ai_hints, 0, sizeof(ai_hints));
            ai_hints.ai_family = AF_UNSPEC;
            ai_hints.ai_socktype = SOCK_DGRAM;
            ai_hints.ai_protocol = 0;
            ai_hints.ai_flags = 0;
            if ((rval = getaddrinfo(optarg, NULL, &ai_hints, &ai_rval)) != 0) {
                fprintf(stderr, "Invalid name/address %s: %s\n",
                        optarg, gai_strerror(rval));
                exit(ERR_PARAM);
            }
            // Just use the first addrinfo entry
            if ((listidx = getifbyaddr((union sockaddr_u *)ai_rval->ai_addr,
                    ifl, ifl_len)) == -1) {
                fprintf(stderr, "Interface %s not found", optarg);
                exit(ERR_PARAM);
            }
            out_if = ifl[listidx];
            freeaddrinfo(ai_rval);
            break;
        case 'z':
            sync_mode = 1;
            break;
        case 'Z':
            sync_preview = 1;
            sync_mode = 1;
            break;
        case 'p':
            strncpy(port, optarg, sizeof(port)-1);
            port[sizeof(port)-1] = '\x0';
            break;
        case 'u':
            strncpy(srcport, optarg, sizeof(srcport)-1);
            srcport[sizeof(srcport)-1] = '\x0';
            break;
        case 'j':
            if (read_restart) {
                fprintf(stderr,"Can't specify both -j and -F\n");
                exit(ERR_PARAM);
            }
            if ((destfile = fopen(optarg, "rt")) == NULL) {
                fprintf(stderr,"Couldn't open proxy list %s: %s\n",
                        optarg, strerror(errno));
                exit(ERR_PARAM);
            }
            while (fgets(line, sizeof(line), destfile)) {
                while ((strlen(line) > 0) && ((line[strlen(line)-1] == '\r') ||
                       (line[strlen(line)-1] == '\n'))) {
                    line[strlen(line)-1] = '\x0';
                }
                destname = strtok(line, "|");
                if (!destname) continue;
                if (destname[0] == '#') continue;
                if (strlen(destname) >= DESTNAME_LEN) {
                    fprintf(stderr, "Proxylist: name too long\n");
                    exit(ERR_PARAM);
                }
                fingerprint = strtok(NULL, " \t");
                add_dest_by_name(destname, fingerprint, 1);
            }
            if (!feof(destfile) && ferror(destfile)) {
                perror("Failed to read from proxylist file");
                exit(ERR_PARAM);
            }
            fclose(destfile);
            break;
        case 'q':
            quit_on_error = 1;
            break;
        case 'f':
            save_fail = 1;
            break;
        case 'y':
            sys_keys = 1;
            break;
        case 'U':
            errno = 0;
            server_id = strtoul(optarg, NULL, 16);
            if (errno) {
                perror("Invalid UID\n");
                exit(ERR_PARAM);
            }
            server_id = htonl(server_id);
            break;
        case 'H':
            if (read_restart) {
                fprintf(stderr,"Can't specify both -H and -F\n");
                exit(ERR_PARAM);
            }
            if (optarg[0] == '@') {
                dest = &optarg[1];
                if ((destfile = fopen(dest, "rt")) == NULL) {
                    fprintf(stderr,"Couldn't open destination list %s: %s\n",
                            dest, strerror(errno));
                    exit(ERR_PARAM);
                }
                while (fgets(line, sizeof(line), destfile)) {
                    while ((strlen(line) > 0) &&
                           ((line[strlen(line)-1] == '\r') ||
                            (line[strlen(line)-1] == '\n'))) {
                        line[strlen(line)-1] = '\x0';
                    }
                    destname = strtok(line, "|");
                    if (!destname) continue;
                    if (destname[0] == '#') continue;
                    if (strlen(destname) >= DESTNAME_LEN) {
                        fprintf(stderr, "Hostlist: name too long\n");
                        exit(ERR_PARAM);
                    }
                    fingerprint = strtok(NULL, " \t");
                    add_dest_by_name(destname, fingerprint, 0);
                }
                if (!feof(destfile) && ferror(destfile)) {
                    perror("Failed to read from hostlist file");
                    exit(ERR_PARAM);
                }
                fclose(destfile);
            } else {
                dest = strtok(optarg, ",");
                while (dest != NULL) {
                    add_dest_by_name(dest, NULL, 0);
                    dest = strtok(NULL, ",");
                }
            }
            break;
        case 'F':
            if (destcount != 0) {
                fprintf(stderr,"Can't specify both -H and -F\n");
                exit(ERR_PARAM);
            }
            read_restart = 1;
            save_fail = 1;
            read_restart_file(optarg);
            break;
        case 'X':
            if ((excludefile = fopen(optarg, "rt")) == NULL) {
                fprintf(stderr,"Couldn't open exclude list %s: %s\n",
                        optarg, strerror(errno));
                exit(ERR_PARAM);
            }
            while (fgets(filename, sizeof(filename), excludefile)) {
                while ((strlen(filename) > 0) &&
                       ((filename[strlen(filename)-1] == '\r') ||
                        (filename[strlen(filename)-1] == '\n'))) {
                    filename[strlen(filename)-1] = '\x0';
                }
                if (strlen(filename) == 0) continue;
                if (excludecount == MAXEXCLUDE) {
                    fprintf(stderr,"Exceeded maximum exclude file count\n");
                    exit(ERR_PARAM);
                }
                strncpy(exclude[excludecount], filename, sizeof(exclude[0]));
                exclude[excludecount][sizeof(exclude[0])-1] = '\x0';
                excludecount++;
            }
            if (!feof(excludefile) && ferror(excludefile)) {
                perror("Failed to read from exclude file");
                exit(ERR_PARAM);
            }
            fclose(excludefile);
            break;
        case 'M':
            strncpy(pub_multi, optarg, sizeof(pub_multi)-1);
            pub_multi[sizeof(pub_multi)-1] = '\x0';
            break;
        case 'P':
            strncpy(priv_multi, optarg, sizeof(priv_multi)-1);
            priv_multi[sizeof(priv_multi)-1] = '\x0';
            break;
        case 'C':
            p = strtok(optarg, ":");
            if (!p) {
                fprintf(stderr, "Error reading cc_type\n");
                exit(ERR_PARAM);
            }
            if (!strcmp(p, "none")) {
                cc_type = CC_NONE;
            } else if (!strcmp(p, "tfmcc")) {
                cc_type = CC_TFMCC;
                p = strtok(NULL, ":");
                if (p) {
                    max_rate = atoi(p);
                    if (max_rate <= 0) {
                        fprintf(stderr,"Invalid max rate\n");
                        exit(ERR_PARAM);
                    }
                    max_rate = max_rate * 1024 / 8;
                }
            } else {
                // PGMCC not currently supported
                fprintf(stderr, "Invalid congestion control type\n");
                exit(ERR_PARAM);
            }
            break;
        case 'D':
            strncpy(destfname, optarg, sizeof(destfname)-1);
            destfname[sizeof(destfname)-1] = '\x0';
            while (destfname[strlen(destfname)-1] == PATH_SEP) {
                destfname[strlen(destfname)-1] = '\x0';
            }
            break;
        case 'o':
            dest_is_dir = 1;
            break;
        case 'E':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(basedir[basedircount], p,
                        sizeof(basedir[basedircount])-1);
                basedir[basedircount][sizeof(basedir[basedircount])-1] = '\x0';
                basedircount++;
                p = strtok(NULL, ",");
            }
            break;
        case 'S':
            strncpy(statusfilename, optarg, sizeof(statusfilename)-1);
            statusfilename[sizeof(statusfilename)-1] = '\x0';
            break;
        case 'r':
            p = strtok(optarg, ":");
            if (!p) {
                fprintf(stderr, "Error reading cc_type\n");
                exit(ERR_PARAM);
            }
            errno = 0;
            grtt = atof(p);
            if (errno) {
                perror("Invalid grtt");
                exit(ERR_PARAM);
            } else if ((grtt < CLIENT_RTT_MIN) || (grtt > 1000)) {
                fprintf(stderr, "Invalid grtt\n");
                exit(ERR_PARAM);
            }
            p = strtok(NULL, ":");
            if (p) {
                errno = 0;
                min_grtt = atof(p);
                if (errno) {
                    perror("Invalid min_grtt");
                    exit(ERR_PARAM);
                } else if ((min_grtt < CLIENT_RTT_MIN) || (min_grtt > 1000)) {
                    fprintf(stderr, "Invalid min_grtt\n");
                    exit(ERR_PARAM);
                }
                p = strtok(NULL, ":");
                if (!p) {
                    fprintf(stderr, "Missing max_grtt\n");
                    exit(ERR_PARAM);
                }
                errno = 0;
                max_grtt = atof(p);
                if (errno) {
                    perror("Invalid max_grtt");
                    exit(ERR_PARAM);
                } else if ((max_grtt < CLIENT_RTT_MIN) || (max_grtt > 1000)) {
                    fprintf(stderr, "Invalid max_grtt\n");
                    exit(ERR_PARAM);
                }
                if (min_grtt > max_grtt) {
                    fprintf(stderr, "Invalid min_grtt/max_grtt\n");
                    exit(ERR_PARAM);
                } else if ((grtt > max_grtt) || (grtt < min_grtt)) {
                    fprintf(stderr, "Invalid grtt\n");
                    exit(ERR_PARAM);
                }
            }
            break;
        case 's':
            robust = atoi(optarg);
            if ((robust < 10) || (robust > 50)) {
                fprintf(stderr,"Invalid robustness factor\n");
                exit(ERR_PARAM);
            }
            break;
        case 'i':
            if (filecount != 0) {
                fprintf(stderr,"Can't specify both -i and -F\n");
                exit(ERR_PARAM);
            }
            if (strcmp(optarg, "-") == 0) {
                listfile = stdin;
            } else if ((listfile = fopen(optarg, "rt")) == NULL) {
                fprintf(stderr,"Couldn't open file list %s: %s\n",
                        optarg, strerror(errno));
                exit(ERR_PARAM);
            }
            while (fgets(filename, sizeof(filename), listfile)) {
                if (filecount == MAXFILES) {
                    fprintf(stderr, "Exceeded maximum file count\n");
                    exit(ERR_PARAM);
                }
                while ((strlen(filename) > 0) &&
                       ((filename[strlen(filename)-1] == '\r') ||
                        (filename[strlen(filename)-1] == '\n'))) {
                    filename[strlen(filename)-1] = '\x0';
                }
                if (strlen(filename) == 0) continue;
                strncpy(filelist[filecount], filename, sizeof(filelist[0])-1);
                filelist[filecount][sizeof(filelist[0])-1] = '\x0';
                filecount++;
            }
            if (!feof(listfile) && ferror(listfile)) {
                perror("Failed to read from file list");
                exit(ERR_PARAM);
            }
            fclose(listfile);
            break;
        case 'W':
            txweight = atoi(optarg);
            if ((txweight < 110) || (txweight > 10000)) {
                fprintf(stderr, "Invalid txweight\n");
                exit(ERR_PARAM);
            }
            break;
        case 'N':
            max_nak_pct = atoi(optarg);
            if ((max_nak_pct < 0) || (max_nak_pct > 100)) {
                fprintf(stderr, "Invalid max_nak_pct\n");
                exit(ERR_PARAM);
            }
            break;
        case '?':
            fprintf(stderr, USAGE);
            exit(ERR_PARAM);
        }
    }
    argc -= optind;
    argv += optind;
    if ((argc == 0) && (filecount == 0)) {
        fprintf(stderr, USAGE);
        exit(ERR_PARAM);
    }

    if (save_fail && sync_mode) {
        fprintf(stderr, "Error: Cannot use restart mode "
                        "and sync mode together\n");
        exit(ERR_PARAM);
    }

    if (keytype == KEY_NONE) {
        hashtype = HASH_NONE;
        sigtype = SIG_NONE;
        keyextype = KEYEX_NONE;
    }
    if (is_auth_enc(keytype)) {
        sigtype = SIG_AUTHENC;
    }
    if (strcmp(keylenstr, "")) {
        if (keyextype == KEYEX_ECDH_ECDSA) {
            ecdsa_curve = get_curve(keylenstr);
            if (ecdsa_curve == 0) {
                fprintf(stderr, "Invalid curve\n");
                exit(ERR_PARAM);
            }
        } else if ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) {
            newkeylen = atoi(keylenstr);
            if ((newkeylen < 512) || (newkeylen > 2048)) {
                fprintf(stderr, "Invalid new key length\n");
                exit(ERR_PARAM);
            }
        }
    }

    if (filecount != 0) {
        if (argc > 0) {
            fprintf(stderr, "Warning: ignoring paths "
                            "specified on command line\n");
        }
        return;
    }
    // Read list of files.
    for (i = 0; i < argc; i++) {
        if (filecount == MAXFILES) {
            fprintf(stderr, "Exceeded maximum file count\n");
            exit(ERR_PARAM);
        }
        strncpy(filelist[filecount], argv[i], sizeof(filelist[0])-1);
        filelist[filecount][sizeof(filelist[0])-1] = '\x0';
        filecount++;
    }
}

