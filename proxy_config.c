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
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <process.h>
#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#endif

#include "proxy.h"
#include "proxy_config.h"

/**
 * Global command line values and sockets
 */
SOCKET listener;
char pidfile[MAXPATHNAME];
char keyfile[MAXLIST][MAXPATHNAME], keyinfo[MAXLIST][MAXPATHNAME];
int proxy_type, debug, rcvbuf, dscp, keyfile_count, keyinfo_count;
int hb_interval, priority;
unsigned int ttl;
char portname[PORTNAME_LEN], out_portname[PORTNAME_LEN];
int port, out_port;
union sockaddr_u down_addr;
int have_down_fingerprint;
uint8_t down_fingerprint[HMAC_LEN];
uint32_t down_nonce, uid;
union sockaddr_u hb_hosts[MAXLIST];
union sockaddr_u pub_multi[MAX_INTERFACES];
struct fp_list_t server_fp[MAXLIST], client_fp[MAXPROXYDEST];
struct iflist ifl[MAX_INTERFACES], m_interface[MAX_INTERFACES];
struct timeval next_hb_time, last_key_req;
int ifl_len, hbhost_count, server_fp_count, client_fp_count;
int keyfile_count, key_count, pub_multi_count, interface_count, sys_keys;
struct iflist out_if;
union key_t privkey[MAXLIST];
int privkey_type[MAXLIST];
union key_t dhkey;
uint8_t ecdh_curve;
struct pr_group_list_t group_list[MAXLIST];

extern char *optarg;
extern int optind;

/**
 * Adds a host and its fingerprint to the given list
 */
void add_hosts_by_name(struct fp_list_t *list, int *list_count,
                       const char *filename, int expect_ip)
{
    char line[1000], *hostid, *ipstr, *fingerprint;
    FILE *hostfile;
    struct addrinfo ai_hints, *ai_rval;
    uint32_t remote_uid;
    int rval;

    if ((hostfile = fopen(filename, "r")) == NULL) {
        fprintf(stderr,"Couldn't open server/client list %s: %s\n",
                filename, strerror(errno));
        exit(ERR_PARAM);
    }
    while (fgets(line, sizeof(line), hostfile)) {
        while (line[strlen(line)-1] == '\r' || line[strlen(line)-1] == '\n') {
            line[strlen(line)-1] = '\x0';
        }
        if ((line[0] == '#') || (line[0] == '\x0')) {
            continue;
        }
        hostid = line;
        ipstr = strchr(hostid, '|');
        if (ipstr) {
            *ipstr = '\x0';
            ipstr++;
            if (expect_ip) {
                fingerprint = strchr(ipstr, '|');
                if (fingerprint) {
                    *fingerprint = '\x0';
                    fingerprint++;
                }
            } else {
                fingerprint = ipstr;
                ipstr = NULL;
            }
        } else {
            fingerprint = NULL;
        }
        if (strlen(hostid) >= DESTNAME_LEN) {
            fprintf(stderr, "Server/Client list %s: name too long\n", filename);
            exit(ERR_PARAM);
        }

        remote_uid = strtoul(hostid, NULL, 16);
        if ((remote_uid == 0xffffffff) || (remote_uid == 0)) {
            fprintf(stderr, "Invalid UID %s\n", hostid);
            exit(ERR_PARAM);
        }

        list[*list_count].uid = htonl(remote_uid);
        if (expect_ip) {
            memset(&ai_hints, 0, sizeof(ai_hints));
            ai_hints.ai_family = AF_UNSPEC;
            ai_hints.ai_socktype = SOCK_DGRAM;
            ai_hints.ai_protocol = 0;
            ai_hints.ai_flags = 0;
            if ((rval = getaddrinfo(ipstr, NULL, &ai_hints, &ai_rval)) != 0) {
                fprintf(stderr, "Invalid host name/address %s: %s\n",
                        ipstr, gai_strerror(rval));
                exit(ERR_PARAM);
            }
            memcpy(&list[*list_count].addr, ai_rval->ai_addr,
                    ai_rval->ai_addrlen);
            freeaddrinfo(ai_rval);
        }
        list[*list_count].has_fingerprint =
            parse_fingerprint(list[*list_count].fingerprint, fingerprint);
        (*list_count)++;
    }
    if (!feof(hostfile) && ferror(hostfile)) {
        perror("Failed to read from server/client list file");
        exit(ERR_PARAM);
    }
    fclose(hostfile);
}

/**
 * Set defaults for all command line arguments
 */
void set_defaults(void)
{
    proxy_type = UNDEF_PROXY;
    hbhost_count =  0;
    memset(hb_hosts, 0, sizeof(hb_hosts));
    hb_interval = DEF_HB_INT;
    debug = 0;
    log_level = DEF_LOG_LEVEL;
    strncpy(portname, DEF_PORT, sizeof(portname)-1);
    portname[sizeof(portname)-1] = '\x0';
    port = atoi(portname);
    memset(&out_if, 0, sizeof(out_if));
    ttl = DEF_TTL;
    dscp = DEF_DSCP;
    strncpy(out_portname, DEF_PORT, sizeof(out_portname)-1);
    out_portname[sizeof(out_portname)-1] = '\x0';
    out_port = atoi(out_portname);
    uid = 0;
    rcvbuf = 0;
    strncpy(logfile, DEF_LOGFILE, sizeof(logfile)-1);
    logfile[sizeof(logfile)-1] = '\x0';
    memset(pidfile, 0, sizeof(pidfile));
    server_fp_count = 0;
    client_fp_count = 0;
    key_count = 0;
    keyfile_count = 0;
    keyinfo_count = 0;
    interface_count = 0;
    pub_multi_count = 0;
    sys_keys = 0;
    priority = 0;
    ecdh_curve = 0;
    max_log_size = 0;
    max_log_count = DEF_MAX_LOG_COUNT;
}

/**
 * Set argument defaults, read and validate command line options
 */
void process_args(int argc, char *argv[])
{
    struct addrinfo ai_hints, *ai_rval;
    int c, i, listidx, rval;
    long tmpval;
    char *p, *p2, *hoststr, *portstr, pubname[INET6_ADDRSTRLEN];
    const char opts[] = "s:crdx:p:t:Q:N:O:U:q:mh:H:g:n:B:L:P:C:S:e:k:K:I:M:";

    set_defaults();
    srand((unsigned int)time(NULL) ^ getpid());

    // read lettered arguments
    while ((c = getopt(argc, argv, opts)) != EOF) {
        switch (c) {
        case 's':
            if (proxy_type != UNDEF_PROXY) {
                fprintf(stderr, "Only one of -s, -c, -r may be specified\n");
                exit(ERR_PARAM);
            }
            proxy_type = SERVER_PROXY;
            memset(&down_addr, 0, sizeof(down_addr));
            if (!strncmp(optarg, "fp=", 3)) {
                have_down_fingerprint =
                        parse_fingerprint(down_fingerprint, optarg + 3);
                if (!have_down_fingerprint) {
                    fprintf(stderr, "Failed to parse downstream fingerprint\n");
                    exit(ERR_PARAM);
                }
                down_nonce = rand32();
            } else {
                have_down_fingerprint = 0;
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(optarg, NULL, &ai_hints,
                        &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid host name: %s: %s\n",
                            optarg, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                memcpy(&down_addr, ai_rval->ai_addr, ai_rval->ai_addrlen);
                freeaddrinfo(ai_rval);
            }
            break;
        case 'c':
            if (proxy_type != UNDEF_PROXY) {
                fprintf(stderr, "Only one of -s, -c, -r may be specified\n");
                exit(ERR_PARAM);
            }
            proxy_type = CLIENT_PROXY;
            break;
        case 'r':
            if (proxy_type != UNDEF_PROXY) {
                fprintf(stderr, "Only one of -s, -c, -r may be specified\n");
                exit(ERR_PARAM);
            }
            proxy_type = RESPONSE_PROXY;
            break;
        case 'd':
            debug = 1;
            break;
        case 'x':
            log_level = atoi(optarg);
            if (log_level < 0) {
                fprintf(stderr, "Invalid log level\n");
                exit(ERR_PARAM);
            }
            break;
        case 'p':
            strncpy(portname, optarg, sizeof(portname)-1);
            portname[sizeof(portname)-1] = '\x0';
            port = atoi(portname);
            if (port == 0) {
                fprintf(stderr, "Invalid port\n");
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
        case 'N':
            priority = atoi(optarg);
            if (!valid_priority(priority)) {
                fprintf(stderr, "Invalid priority value\n");
                exit(ERR_PARAM);
            }
            break;
        case 'O':
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
        case 'U':
            errno = 0;
            uid = strtoul(optarg, NULL, 16);
            if (errno) {
                perror("Invalid UID\n");
                exit(ERR_PARAM);
            }
            uid = htonl(uid);
            break;
        case 'q':
            strncpy(out_portname, optarg, sizeof(out_portname)-1);
            out_portname[sizeof(out_portname)-1] = '\x0';
            out_port = atoi(out_portname);
            if (out_port == 0) {
                fprintf(stderr, "Invalid outgoing port\n");
                exit(ERR_PARAM);
            }
            break;
        case 'm':
            sys_keys = 1;
            break;
        case 'H':
            p = strtok(optarg, ",");
            while (p != NULL) {
                p2 = strchr(p, ':');
                if (p2) {
                    hoststr = strdup(p);
                    hoststr[p2 - p] = '\x0';
                    portstr = p2 + 1;
                } else {
                    hoststr = p;
                    portstr = NULL;
                }
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(hoststr, portstr ? portstr : DEF_PORT,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid name/address %s: %s\n",
                            hoststr, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                memcpy(&hb_hosts[hbhost_count++], ai_rval->ai_addr,
                        ai_rval->ai_addrlen);
                p = strtok(NULL, ",");
            }
            break;
        case 'h':
            hb_interval = atoi(optarg);
            if ((hb_interval <= 0) || (hb_interval > 3600)) {
                fprintf(stderr, "Invalid heartbeat interval\n");
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
        case 'B':
            rcvbuf = atoi(optarg);
            if ((rcvbuf < 65536) || (rcvbuf > 104857600)) {
                fprintf(stderr, "Invalid buffer size\n");
                exit(ERR_PARAM);
            }
            break;
        case 'L':
            strncpy(logfile, optarg, sizeof(logfile)-1);
            logfile[sizeof(logfile)-1] = '\x0';
            break;
        case 'P':
            strncpy(pidfile, optarg, sizeof(pidfile)-1);
            pidfile[sizeof(pidfile)-1] = '\x0';
            break;
        case 'C':
            add_hosts_by_name(client_fp, &client_fp_count, optarg, 0);
            break;
        case 'S':
            add_hosts_by_name(server_fp, &server_fp_count, optarg, 1);
            break;
        case 'e':
            ecdh_curve = get_curve(optarg);
            if (ecdh_curve == 0) {
                fprintf(stderr, "Invalid curve\n");
                exit(ERR_PARAM);
            }
            break;
        case 'k':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(keyfile[keyfile_count], p, sizeof(keyfile[0])-1);
                keyfile[keyfile_count][sizeof(keyfile[0])-1] = '\x0';
                keyfile_count++;
                p = strtok(NULL, ",");
            }
            break;
        case 'K':
            p = strtok(optarg, ",");
            while (p != NULL) {
                strncpy(keyinfo[keyinfo_count], p, sizeof(keyinfo[0])-1);
                keyinfo[keyinfo_count][sizeof(keyinfo[0])-1] = '\x0';
                keyinfo_count++;
                p = strtok(NULL, ",");
            }
            break;
        case 'I':
            p = strtok(optarg, ",");
            while (p != NULL) {
                if ((listidx = getifbyname(p, ifl, ifl_len)) != -1) {
                    m_interface[interface_count++] = ifl[listidx];
                    p = strtok(NULL, ",");
                    continue;
                }
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(p, NULL,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid name/address %s: %s\n",
                            p, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                if ((listidx = getifbyaddr((union sockaddr_u *)ai_rval->ai_addr,
                        ifl, ifl_len)) == -1) {
                    fprintf(stderr, "Interface %s not found\n", p);
                    exit(ERR_PARAM);
                }
                m_interface[interface_count++] = ifl[listidx];
                freeaddrinfo(ai_rval);
                p = strtok(NULL, ",");
            }
            break;
        case 'M':
            p = strtok(optarg, ",");
            while (p != NULL) {
                memset(&ai_hints, 0, sizeof(ai_hints));
                ai_hints.ai_family = AF_UNSPEC;
                ai_hints.ai_socktype = SOCK_DGRAM;
                ai_hints.ai_protocol = 0;
                ai_hints.ai_flags = 0;
                if ((rval = getaddrinfo(p, NULL,
                        &ai_hints, &ai_rval)) != 0) {
                    fprintf(stderr, "Invalid multicast address %s: %s\n",
                            p, gai_strerror(rval));
                    exit(ERR_PARAM);
                }
                memcpy(&pub_multi[pub_multi_count], ai_rval->ai_addr,
                        ai_rval->ai_addrlen);
                pub_multi_count++;
                freeaddrinfo(ai_rval);
                p = strtok(NULL, ",");
            }
            break;
        case '?':
            fprintf(stderr, USAGE);
            exit(ERR_PARAM);
        }
    }

    if (proxy_type == UNDEF_PROXY) {
        fprintf(stderr, "Either -s, -c, or -r must be specified\n");
        fprintf(stderr, USAGE);
        exit(ERR_PARAM);
    }
    if (proxy_type == RESPONSE_PROXY) {
        out_port = port;
    }
    if (proxy_type == SERVER_PROXY) {
        if (down_addr.ss.ss_family == AF_INET6) {
            down_addr.sin6.sin6_port = htons(out_port);
        } else {
            down_addr.sin.sin_port = htons(out_port);
        }
    }
    if (proxy_type != CLIENT_PROXY) {
        if (server_fp_count) {
            for (i = 0; i < pub_multi_count; i++) {
                if (!is_multicast(&pub_multi[i], 1)) {
                    if ((rval = getnameinfo((struct sockaddr *)&pub_multi[i],
                            family_len(pub_multi[i]), pubname, sizeof(pubname),
                            NULL, 0, NI_NUMERICHOST)) != 0) {
                        fprintf(stderr,"getnameinfo failed: %s",
                                gai_strerror(rval));
                    }
                    fprintf(stderr, "Invalid source specific "
                            "multicast address: %s\n", pubname);
                    exit(ERR_PARAM);
                }
            }
            if (pub_multi_count == 0) {
                fprintf(stderr, "Default multicast address %s invalid "
                        "for source specific multicast\n", DEF_PUB_MULTI);
                exit(ERR_PARAM);
            }
        }
    }
    if ((keyfile_count != 0) && (keyinfo_count != 0) &&
            (keyfile_count != keyinfo_count)) {
        fprintf(stderr, "Must list same number of items for -k and -K\n");
        exit(ERR_PARAM);
    }
    for (i = 0; i < pub_multi_count; i++) {
        if (pub_multi[i].ss.ss_family == AF_INET6) {
            pub_multi[i].sin6.sin6_port = htons(out_port);
        } else {
            pub_multi[i].sin.sin_port = htons(out_port);
        }
    }
}

