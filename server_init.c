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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <process.h>
#include <ws2tcpip.h>
#include <io.h>

#else  // if WINDOWS

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "server.h"
#include "server_config.h"
#include "server_init.h"

/**
 * Cleanup routine set up by atexit
 */
void cleanup(void)
{
    int i;

    closesocket(sock);
    for (i = 0; i < destcount; i++) {
        if (keytype != KEY_NONE) {
            if (destlist[i].encinfo) {
                if (destlist[i].encinfo->pubkey.key) {
                    if ((keyextype == KEYEX_RSA) ||
                            (keyextype == KEYEX_ECDH_RSA)) {
                        free_RSA_key(destlist[i].encinfo->pubkey.rsa);
                    } else {
                        free_EC_key(destlist[i].encinfo->pubkey.ec);
                    }
                    if ((keyextype == KEYEX_ECDH_RSA) ||
                            (keyextype == KEYEX_ECDH_ECDSA)) {
                        free_EC_key(destlist[i].encinfo->dhkey.ec);
                    }
                }
                free(destlist[i].encinfo);
            }
        }
        if (destlist[i].clients) {
            free(destlist[i].clients);
        }
    }
    if (keytype != KEY_NONE) {
        if ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) {
            free_RSA_key(privkey.rsa);
        } else {
            free_EC_key(privkey.ec);
        }
        if ((keyextype == KEYEX_ECDH_RSA) || (keyextype == KEYEX_ECDH_ECDSA)) {
            free_EC_key(dhkey.ec);
        }
    }
    crypto_cleanup();

#ifdef WINDOWS
    WSACleanup();
#endif
}

/**
 * Do initial setup before parsing arguments, including getting interface list
 */
void pre_initialize()
{
#ifdef WINDOWS
    struct WSAData data;

    if (WSAStartup(2, &data)) {
        fprintf(stderr, "Error in WSAStartup: %d\n", WSAGetLastError());
        exit(1);
    }
#endif
    applog = stderr;
    ifl_len = sizeof(ifl) / sizeof(struct iflist);
    getiflist(ifl, &ifl_len);
    srand((unsigned int)time(NULL) ^ getpid());
    crypto_init(0);
}

/**
 * Do all socket creation and initialization
 */
void create_sockets()
{
    struct addrinfo ai_hints, *ai_rval;
    union sockaddr_u su;
    char *p, tmp_multi[INET6_ADDRSTRLEN];
    int found_if, fdflag, bcast, rval, i, s_port;

    // Set up global sockaddr_u structs for public and private addresses
    // Perform octet substitution on private multicast address
    // Make sure public, private, and interface addrs are the same IP version
    memset(&ai_hints, 0, sizeof(ai_hints));
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_DGRAM;
    ai_hints.ai_protocol = 0;
    ai_hints.ai_flags = 0;
    if ((rval = getaddrinfo(pub_multi, dest_port, &ai_hints, &ai_rval)) != 0) {
        log0(0, 0, "Invalid public address or port: %s", gai_strerror(rval));
        exit(1);
    }
    memcpy(&listen_dest, ai_rval->ai_addr, ai_rval->ai_addrlen);
    freeaddrinfo(ai_rval);

    if (!is_multicast(&listen_dest, 0)) {
        receive_dest = listen_dest;
    } else {
        if (listen_dest.ss.ss_family == AF_INET6) {
            while ((p = strchr(priv_multi,'x')) != NULL) {
                memset(tmp_multi, 0, sizeof(tmp_multi));
                snprintf(tmp_multi, sizeof(tmp_multi), "%.*s%x%s",
                       (int)(p - priv_multi), priv_multi, rand() & 0xFFFF, p+1);
                strncpy(priv_multi, tmp_multi, sizeof(priv_multi));
                priv_multi[sizeof(priv_multi)-1] = '\x0';
            }
        } else {
            while ((p = strchr(priv_multi,'x')) != NULL) {
                memset(tmp_multi, 0, sizeof(tmp_multi));
                snprintf(tmp_multi, sizeof(tmp_multi), "%.*s%d%s",
                         (int)(p - priv_multi), priv_multi, rand() & 0xFF, p+1);
                strncpy(priv_multi, tmp_multi, sizeof(priv_multi));
                priv_multi[sizeof(priv_multi)-1] = '\x0';
            }
        }
        if ((rval = getaddrinfo(priv_multi, dest_port, &ai_hints, &ai_rval)) != 0) {
            log0(0, 0, "Invalid private address: %s", gai_strerror(rval));
            exit(1);
        }
        memcpy(&receive_dest, ai_rval->ai_addr, ai_rval->ai_addrlen);
        freeaddrinfo(ai_rval);
    }

    if (!strcmp(out_if.name, "")) {
        for (i = 0, found_if = 0; (i < ifl_len) && !found_if; i++) {
            if ((ifl[i].su.ss.ss_family == listen_dest.ss.ss_family) &&
                    (!ifl[i].isloopback)) {
                found_if = 1;
                out_if = ifl[i];
            }
        }
        if (!found_if) {
            for (i = 0, found_if = 0; (i < ifl_len) && !found_if; i++) {
                if (ifl[i].su.ss.ss_family == listen_dest.ss.ss_family) {
                    found_if = 1;
                    out_if = ifl[i];
                }
            }
        }
        if (!found_if) {
            log0(0, 0, "ERROR: no network interface found for family");
            exit(1);
        }
    }
    if (out_if.su.ss.ss_family == AF_INET6) {
        server_id = out_if.su.sin6.sin6_addr.s6_addr[12] << 24;
        server_id |= out_if.su.sin6.sin6_addr.s6_addr[13] << 16;
        server_id |= out_if.su.sin6.sin6_addr.s6_addr[14] << 8;
        server_id |= out_if.su.sin6.sin6_addr.s6_addr[15];
    } else {
        server_id = ntohl(out_if.su.sin.sin_addr.s_addr);
    }

    if (listen_dest.ss.ss_family != receive_dest.ss.ss_family) {
        log0(0, 0, "IP version mismatch between public and private addresses");
        exit(1);
    }
    if (listen_dest.ss.ss_family != out_if.su.ss.ss_family) {
        log0(0,0, "IP version mismatch between public and interface addresses");
        exit(1);
    }

    // Create and bind socket
    if ((sock = socket(listen_dest.ss.ss_family, SOCK_DGRAM, 0)) ==
            INVALID_SOCKET) {
        sockerror(0, 0, "Error creating socket");
        exit(1);
    }
    memset(&su, 0, sizeof(su));
    su.ss.ss_family = listen_dest.ss.ss_family;
    s_port = atoi(src_port);
    if (su.ss.ss_family == AF_INET)
      su.sin.sin_port = htons(s_port);
    else if  (su.ss.ss_family == AF_INET6)
      su.sin6.sin6_port = htons(s_port);

    if (bind(sock, (struct sockaddr *)&su, family_len(su)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error binding socket");
        exit(1);
    }

    // Set send/receive buffer size, ttl, and multicast interface
    if (rcvbuf) {
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, 
                       sizeof(rcvbuf)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting receive buffer size");
            exit(1);
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&rcvbuf, 
                       sizeof(rcvbuf)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting send buffer size");
            exit(1);
        }
    } else {
        rcvbuf = DEF_RCVBUF;
        if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, 
                       sizeof(rcvbuf)) == SOCKET_ERROR) {
            rcvbuf = DEF_BSD_RCVBUF;
            if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, 
                           sizeof(rcvbuf)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error setting receive buffer size");
                exit(1);
            }
        }
        rcvbuf = DEF_RCVBUF;
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&rcvbuf, 
                       sizeof(rcvbuf)) == SOCKET_ERROR) {
            rcvbuf = DEF_BSD_RCVBUF;
            if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&rcvbuf, 
                           sizeof(rcvbuf)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error setting send buffer size");
                exit(1);
            }
        }
    }
    bcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&bcast, 
                   sizeof(bcast)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error enabling broadcast");
        closesocket(sock);
        exit(1);
    }
    if (listen_dest.ss.ss_family == AF_INET6) {
#ifdef IPV6_MTU_DISCOVER
        {
            int mtuflag = IP_PMTUDISC_DONT;
            if (setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                           (char *)&mtuflag, sizeof(mtuflag)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error disabling MTU discovery");
                closesocket(sock);
                exit(1);
            }
        }
#endif
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&ttl, 
                       sizeof(ttl)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting ttl");
            closesocket(sock);
            exit(1);
        }
#if defined IPV6_TCLASS && !defined WINDOWS
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, (char *)&dscp, 
                       sizeof(dscp)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting dscp");
            closesocket(sock);
            exit(1);
        }
#endif
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                (char *)&out_if.ifidx, sizeof(int)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting outgoing interface");
            closesocket(sock);
            exit(1);
        }
    } else {
        char l_ttl = ttl & 0xFF;
#ifdef IP_MTU_DISCOVER
        {
            int mtuflag = IP_PMTUDISC_DONT;
            if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, (char *)&mtuflag, 
                           sizeof(mtuflag)) == SOCKET_ERROR) {
                sockerror(0, 0, "Error disabling MTU discovery");
                closesocket(sock);
                exit(1);
            }
        }
#endif
        if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &l_ttl, 
                       sizeof(l_ttl)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting ttl");
            closesocket(sock);
            exit(1);
        }
        if (setsockopt(sock, IPPROTO_IP, IP_TOS, (char *)&dscp, 
                       sizeof(dscp)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting dscp");
            closesocket(sock);
            exit(1);
        }
        if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
                       (char *)&out_if.su.sin.sin_addr, 
                       sizeof(out_if.su.sin.sin_addr)) == SOCKET_ERROR) {
            sockerror(0, 0, "Error setting outgoing interface");
            closesocket(sock);
            exit(1);
        }
    }

    // Make socket non-blocking
#ifndef BLOCKING
#ifdef WINDOWS
    fdflag = 1;
    if (ioctlsocket(sock, FIONBIO, &fdflag) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting non-blocking option");
        closesocket(sock);
        exit(1);
    }
#else
    if ((fdflag = fcntl(sock, F_GETFL)) == SOCKET_ERROR) {
        sockerror(0, 0, "Error getting socket descriptor flags");
        closesocket(sock);
        exit(1);
    }
    fdflag |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, fdflag) == SOCKET_ERROR) {
        sockerror(0, 0, "Error setting non-blocking option");
        closesocket(sock);
        exit(1);
    }
#endif
#endif  // BLOCKING
}

/**
 * Initialize crypto library, generate keys
 */
void key_init()
{
    unsigned char *prf_buf;
    time_t t;
    uint32_t t2;
    int explen, len;

    if (keytype == KEY_NONE) {
        return;
    }

    set_sys_keys(sys_keys);
    get_key_info(keytype, &keylen, &ivlen);
    hmaclen = get_hash_len(hashtype);

    memset(groupkey, 0, sizeof(groupkey));
    memset(groupsalt, 0, sizeof(groupsalt));
    memset(grouphmackey, 0, sizeof(grouphmackey));

    if (!get_random_bytes(groupmaster, sizeof(groupmaster))) {
        log0(0, 0, "Failed to generate group master");
        exit(1);
    }
    groupmaster[0] = UFTP_VER_NUM;
    if (!get_random_bytes(rand1, sizeof(rand1))) {
        log0(0, 0, "Failed to generate rand1");
        exit(1);
    }
    // Sets the first 4 bytes of rand1 to the current time
    t = time(NULL);
    t2 = (uint32_t)(t & 0xFFFFFFFF);
    *(uint32_t *)rand1 = t2;

    explen = hmaclen + keylen + SALT_LEN;
    prf_buf = calloc(explen + hmaclen, 1);
    if (prf_buf == NULL) {
        syserror(0, 0, "calloc failed!");
        exit(1);
    }
    PRF(hashtype, explen, groupmaster, sizeof(groupmaster), "key expansion",
            rand1, sizeof(rand1), prf_buf, &len);
    memcpy(grouphmackey, prf_buf, hmaclen);
    memcpy(groupkey, prf_buf + hmaclen, keylen);
    memcpy(groupsalt, prf_buf + hmaclen + keylen, SALT_LEN);
    ivctr = 0;
    free(prf_buf);

    if ((keyextype == KEYEX_RSA) || (keyextype == KEYEX_ECDH_RSA)) {
        if ((!strcmp(keyfile, "")) || (newkeylen != 0)) {
            privkey.rsa = gen_RSA_key(newkeylen, RSA_EXP, keyfile);
        } else {
            privkey.rsa = read_RSA_key(keyfile);
        }
        if (!privkey.key) {
            log0(0, 0, "Failed to read/generate private key");
            exit(1);
        }
        privkeylen = RSA_keylen(privkey.rsa);
    } else {
        if ((!strcmp(keyfile, "")) || (ecdsa_curve != 0)) {
            privkey.ec = gen_EC_key(ecdsa_curve, 0, keyfile);
        } else {
            privkey.ec = read_EC_key(keyfile);
        }
        if (!privkey.key) {
            log0(0, 0, "Failed to read/generate private key");
            exit(1);
        }
        privkeylen = ECDSA_siglen(privkey.ec);
    }
    if ((keyextype == KEYEX_ECDH_RSA) || (keyextype == KEYEX_ECDH_ECDSA)) {
        dhkey.ec = gen_EC_key(ecdh_curve, 1, NULL);
        if (!dhkey.key) {
            log0(0, 0, "Failed to generate DH key");
            exit(1);
        }
    }
}

/**
 * Initialization based on command line args
 */
void initialize()
{
    atexit(cleanup);

    if (strcmp(logfile, "")) {
        int fd;
        if ((fd = open(logfile, O_WRONLY | O_APPEND | O_CREAT, 0644)) == -1) {
            perror("Can't open log file");
            exit(1);
        }
        dup2(fd, 2);
        close(fd);
        showtime = 1;
    }
    applog = stderr;

    key_init();
    create_sockets();

    // Size of data packet, used in transmission speed calculations
    datapacketsize = blocksize + sizeof(struct fileseg_h);
    if (cc_type == CC_TFMCC) {
        datapacketsize += sizeof(struct tfmcc_data_info_he);
    }
    if (keytype != KEY_NONE) {
        datapacketsize += ((sigtype == SIG_KEYEX) ? privkeylen :
                (sigtype == SIG_HMAC) ? hmaclen : 0) +
                KEYBLSIZE + sizeof(struct encrypted_h);
    }
    // 8 = UDP size, 20 = IPv4 size, 40 = IPv6 size
    if (listen_dest.ss.ss_family == AF_INET6) {
        datapacketsize += sizeof(struct uftp_h) + 8 + 40;
    } else {
        datapacketsize += sizeof(struct uftp_h) + 8 + 20;
    }

    // Never ask for a client key with no encryption,
    // and always ask with RSA/ECDSA signatures
    if (keytype == KEY_NONE) {
        client_auth = 0;
    } else if (sigtype == SIG_KEYEX) {
        client_auth = 1;
    }

    if (cc_type == CC_NONE || cc_type == CC_UFTP3) {
        if (rate == -1) {
            packet_wait = 0;
        } else {
            packet_wait = (int32_t)(1000000.0 * datapacketsize / rate);
        }
    } else if (cc_type == CC_TFMCC) {
        // Initialize the rate to the default rate for control message timing
        packet_wait = (int32_t)(1000000.0 * datapacketsize / rate);
    }
}

