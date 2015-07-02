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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#ifdef WINDOWS

#include <process.h>
#include <ws2tcpip.h>
#include <io.h>

#include "win_func.h"

#else // WINDOWS

#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#endif

#include "proxy.h"
#include "proxy_init.h"
#include "proxy_config.h"
#include "proxy_common.h"

static int parent;  // is this the parent process that exits after a fork?

/**
 * Cleanup routine set up by atexit
 */
void cleanup(void)
{
    int i;

    for (i = 0; i < MAXLIST; i++) {
        if (group_list[i].group_id != 0) {
            group_cleanup(&group_list[i]);
        }
    }
    if (!parent) {
        for (i = 0; i < pub_multi_count; i++) {
            multicast_leave(listener, 0, &pub_multi[i], m_interface,
                            interface_count, server_fp, server_fp_count);
        }
    }
    closesocket(listener);

    for (i = 0; i < key_count; i++) {
        if (privkey_type[i] == KEYBLOB_RSA) {
            free_RSA_key(privkey[i].rsa);
        } else {
            free_EC_key(privkey[i].ec);
        }
    }
    crypto_cleanup();

#ifdef WINDOWS
    WSACleanup();
#endif
    fclose(stderr);
}

/**
 * Generic signal handler, exits on signal
 */
void gotsig(int sig)
{
    log0(0, 0, 0, "Exiting on signal %d", sig);
    exit(ERR_INTERRUPTED);
}

#ifdef WINDOWS
/**
 * Windows event handler, exits
 */
BOOL WINAPI winsig(DWORD event)
{
    switch (event) {
    case CTRL_C_EVENT:
        log0(0, 0, 0, "Got CTRL_C_EVENT");
        break;
    case CTRL_BREAK_EVENT:
        log0(0, 0, 0, "Got CTRL_BREAK_EVENT");
        break;
    case CTRL_CLOSE_EVENT:
        log0(0, 0, 0, "Got CTRL_CLOSE_EVENT");
        break;
    case CTRL_LOGOFF_EVENT:
        log0(0, 0, 0, "Got CTRL_LOGOFF_EVENT");
        break;
    case CTRL_SHUTDOWN_EVENT:
        log0(0, 0, 0, "Got CTRL_SHUTDOWN_EVENT");
        break;
    default:
        log0(0, 0, 0, "GOT unknown event %d", event);
        break;
    }
    exit(ERR_INTERRUPTED);
}
#endif

/**
 * Do initial setup before parsing arguments, including getting interface list
 */
void pre_initialize(void)
{
#ifdef WINDOWS
    struct WSAData data;

    if (WSAStartup(2, &data)) {
        fprintf(stderr, "Error in WSAStartup: %d\n", WSAGetLastError());
        exit(ERR_SOCKET);
    }
#endif
    applog = stderr;
    ifl_len = sizeof(ifl) / sizeof(struct iflist);
    getiflist(ifl, &ifl_len);
}

/**
 * Set up log file and run in the backgroud
 */
void daemonize(void)
{
    showtime = 1;
    init_log_mux = 0;
#ifdef WINDOWS
    init_log(debug);
    if (!debug) {
        FILE *pidfh;

        if (strcmp(pidfile, "")) {
            // Write out the pid file, before we redirect STDERR to the log.
            if ((pidfh = fopen(pidfile, "w")) == NULL) {
                syserror(0, 0, 0, "Can't open pid file for writing");
                exit(ERR_PARAM);
            }
            fprintf(pidfh, "%d\n", GetCurrentProcessId());
            fclose(pidfh);
        }
    }

    if (!SetPriorityClass(GetCurrentProcess(), get_win_priority(priority))) {
        char errbuf[300];
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
                GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
        log0(0,0,0, "Error setting priority (%d): %s", GetLastError(), errbuf);
    }
    SetConsoleCtrlHandler(winsig, TRUE);
#else  // WINDOWS
    if (!debug) {
        int pid, fd;
        FILE *pidfh;

        if ((pid = fork()) == -1) {
            perror("Couldn't fork");
            exit(ERR_ALLOC);
        } else if (pid > 0) {
            parent = 1;
            exit(ERR_NONE);
        }
        setsid();
        for (fd = 0; fd < 30; fd++) {
            if ((fd != 2) && (fd != listener)) {
                close(fd);
            }
        }
#ifdef VMS
        chdir("SYS$LOGIN");
#else
        chdir("/");
#endif
        umask(0);

        init_log(debug);
        if (strcmp(pidfile, "")) {
            // Write out the pid file, before we redirect STDERR to the log.
            if ((pidfh = fopen(pidfile, "w")) == NULL) {
                perror("Can't open pid file for writing");
                exit(ERR_PARAM);
            }
            fprintf(pidfh, "%d\n", getpid());
            fclose(pidfh);
        }
    }

    if (nice(priority) == -1) {
        syserror(0, 0, 0, "Error setting priority");
    }
    {
        struct sigaction act;

        sigfillset(&act.sa_mask);
        act.sa_flags = SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESTART;

        act.sa_handler = gotsig;
        sigaction(SIGINT, &act, NULL);
        sigaction(SIGTERM, &act, NULL);
        act.sa_handler = SIG_IGN;
        sigaction(SIGPIPE, &act, NULL);
        sigaction(SIGCHLD, &act, NULL);
    }
#endif  // WINDOWS
}

/**
 * Initialize crypto library, generate keys
 */
void key_init(void)
{
#ifndef NO_ENCRYPTION
    char *keyname;
    int size, i;
    uint8_t curve;

    crypto_init(sys_keys);

    if ((keyfile_count == 0) && (keyinfo_count == 0)) {
        privkey[0].rsa = gen_RSA_key(0, RSA_EXP, NULL);
        if (!privkey[0].key) {
            exit(ERR_CRYPTO);
        }
        privkey_type[0] = KEYBLOB_RSA;
        key_count = 1;
    } else if (keyinfo_count != 0) {
        key_count = 0;
        for (i = 0; i < keyinfo_count; i++) {
            if (keyfile_count <= i) {
                keyname = NULL;
            } else {
                keyname = keyfile[i];
            }
            if (!strncmp(keyinfo[i], "ec:", 3)) {
                curve = get_curve(&keyinfo[i][3]);
                if (curve == 0) {
                    log0(0, 0, 0, "Invalid EC curve: %s", &keyinfo[i][3]);
                    exit(ERR_PARAM);
                }
                privkey[key_count].ec = gen_EC_key(curve, 0, keyname);
                privkey_type[key_count] = KEYBLOB_EC;
                if (!privkey[key_count].key) {
                    exit(ERR_CRYPTO);
                }
            } else if (!strncmp(keyinfo[i], "rsa:", 4)) {
                size = atoi(&keyinfo[i][4]);
                if ((size < 512) || (size > 2048)) {
                    log0(0, 0, 0, "Invalid RSA key size: %s", &keyinfo[i][4]);
                    exit(ERR_PARAM);
                }
                privkey[key_count].rsa = gen_RSA_key(size, RSA_EXP, keyname);
                privkey_type[key_count] = KEYBLOB_RSA;
                if (!privkey[key_count].key) {
                    exit(ERR_CRYPTO);
                }
            } else {
                log0(0, 0, 0, "Invalid keyinfo entry: %s", keyinfo[i]);
                exit(ERR_PARAM);
            }
            key_count++;
        }
    } else {
        for (i = 0; i < keyfile_count; i++) {
            privkey[key_count] =
                    read_private_key(keyfile[i], &privkey_type[key_count]);
            if (privkey_type[key_count] == 0) {
                exit(ERR_CRYPTO);
            }
            key_count++;
        }
    }
    if ((proxy_type == RESPONSE_PROXY) && (ecdh_curve != 0)) {
        dhkey.ec = gen_EC_key(ecdh_curve, 1, NULL);
        if (!dhkey.key) {
            log0(0, 0, 0, "Failed to generate DH key");
            exit(ERR_CRYPTO);
        }
    }
#endif
}

/**
 * Do all socket creation and initialization
 */
void create_sockets(void)
{
    struct addrinfo ai_hints, *ai_rval;
    int family, found_if, rval, fdflag, i;
#if (defined IPV6_RECVTCLASS || defined IP_RECVTCLASS || defined IP_RECVTOS) &&\
        !(defined WINDOWS && _WIN32_WINNT < _WIN32_WINNT_LONGHORN)
    int tosflag;
#endif

    if (!strcmp(out_if.name, "")) {
        for (i = 0, found_if = 0; (i < ifl_len) && !found_if; i++) {
            if ((ifl[i].su.ss.ss_family == AF_INET) &&
                    (!ifl[i].isloopback)) {
                found_if = 1;
                out_if = ifl[i];
            }
        }
        if (!found_if) {
            for (i = 0, found_if = 0; (i < ifl_len) && !found_if; i++) {
                if (ifl[i].su.ss.ss_family == AF_INET) {
                    found_if = 1;
                    out_if = ifl[i];
                }
            }
        }
        if (!found_if) {
            log0(0, 0, 0, "ERROR: no network interface found for family");
            exit(ERR_SOCKET);
        }
    }
    if (out_if.su.ss.ss_family == AF_INET6) {
        out_if.su.sin6.sin6_port = htons(port);
    } else {
        out_if.su.sin.sin_port = htons(port);
    }

    if (proxy_type == CLIENT_PROXY) {
        family = out_if.su.ss.ss_family;
        for (i = 0; i < hbhost_count; i++) {
            if (hb_hosts[i].ss.ss_family == AF_INET6) {
                family = AF_INET6;
                break;
            }
        }
    } else {
        family = AF_INET;
        for (i = 0; i < pub_multi_count; i++) {
            if (pub_multi[i].ss.ss_family == AF_INET6) {
                family = AF_INET6;
                break;
            }
        }
        if ((proxy_type == SERVER_PROXY) &&
                (down_addr.ss.ss_family == AF_INET6)) {
            family = AF_INET6;
        }
    }

    if ((listener = socket(family, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        sockerror(0, 0, 0, "Error creating socket for listener");
        exit(ERR_SOCKET);
    }
#if (defined WINDOWS && _WIN32_WINNT >= _WIN32_WINNT_LONGHORN) ||\
        (!defined WINDOWS && !defined NO_DUAL)
    if (family == AF_INET6) {
        int v6flag = 0;
        if (setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6flag,
                        sizeof(v6flag)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting v6only");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
    }
#endif
    memset(&ai_hints, 0, sizeof(ai_hints));
    ai_hints.ai_family = family;
    ai_hints.ai_socktype = SOCK_DGRAM;
    ai_hints.ai_protocol = 0;
    ai_hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    if ((rval = getaddrinfo(NULL, portname, &ai_hints, &ai_rval)) != 0) {
        log0(0, 0, 0, "Error getting bind address: %s", gai_strerror(rval));
        exit(ERR_SOCKET);
    }
    if (bind(listener, ai_rval->ai_addr, ai_rval->ai_addrlen) == SOCKET_ERROR) {
        sockerror(0, 0, 0, "Error binding socket for listener");
        closesocket(listener);
        exit(ERR_SOCKET);
    }
    freeaddrinfo(ai_rval);

#ifdef WINDOWS
    fdflag = 1;
    if (ioctlsocket(listener, FIONBIO, &fdflag) == SOCKET_ERROR) {
        sockerror(0, 0, 0, "Error setting non-blocking option");
        closesocket(listener);
        exit(ERR_SOCKET);
    }
#else
    if ((fdflag = fcntl(listener, F_GETFL)) == SOCKET_ERROR) {
        sockerror(0, 0, 0, "Error getting socket descriptor flags");
        closesocket(listener);
        exit(ERR_SOCKET);
    }
    fdflag |= O_NONBLOCK;
    if (fcntl(listener, F_SETFL, fdflag) == SOCKET_ERROR) {
        sockerror(0, 0, 0, "Error setting non-blocking option");
        closesocket(listener);
        exit(ERR_SOCKET);
    }
#endif
    if (family == AF_INET6) {
#if defined IPV6_TCLASS && !defined WINDOWS
        if (setsockopt(listener, IPPROTO_IPV6, IPV6_TCLASS, (char *)&dscp,
                       sizeof(dscp)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting dscp");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
#endif
#ifdef IPV6_RECVTCLASS
#if !(defined WINDOWS && _WIN32_WINNT < _WIN32_WINNT_LONGHORN)
        tosflag = 1;
        if (setsockopt(listener, IPPROTO_IPV6, IPV6_RECVTCLASS,
                       (char *)&tosflag, sizeof(tosflag)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting recv tos");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
#endif
#endif
        if (setsockopt(listener, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                       (char *)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting ttl");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
#ifdef IPV6_MTU_DISCOVER
        {
            int mtuflag = IP_PMTUDISC_DONT;
            if (setsockopt(listener, IPPROTO_IPV6, IPV6_MTU_DISCOVER,
                           (char *)&mtuflag, sizeof(mtuflag)) == SOCKET_ERROR) {
                sockerror(0, 0, 0, "Error disabling MTU discovery");
                closesocket(listener);
                exit(ERR_SOCKET);
            }
        }
#endif
        if (setsockopt(listener, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                (char *)&out_if.ifidx, sizeof(int)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting outgoing interface");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
    } else {
        if (setsockopt(listener, IPPROTO_IP, IP_MULTICAST_IF,
                (char *)&out_if.su.sin.sin_addr,
                sizeof(out_if.su.sin.sin_addr)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting outgoing interface");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
    }
#if (defined WINDOWS && _WIN32_WINNT < _WIN32_WINNT_LONGHORN) ||\
        (defined NO_DUAL)
    if (family == AF_INET) {
#endif
        if (setsockopt(listener, IPPROTO_IP, IP_TOS, (char *)&dscp,
                       sizeof(dscp)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting dscp");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
#ifdef IP_RECVTCLASS
#if !(defined WINDOWS && _WIN32_WINNT < _WIN32_WINNT_LONGHORN)
        tosflag = 1;
        if (setsockopt(listener, IPPROTO_IP, IP_RECVTCLASS, (char *)&tosflag,
                       sizeof(tosflag)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting recv tos");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
#endif
#elif defined IP_RECVTOS
        tosflag = 1;
        if (setsockopt(listener, IPPROTO_IP, IP_RECVTOS, (char *)&tosflag,
                       sizeof(tosflag)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting recv tos");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
#endif
#ifdef IP_MTU_DISCOVER
        {
            int mtuflag = IP_PMTUDISC_DONT;
            if (setsockopt(listener, IPPROTO_IP, IP_MTU_DISCOVER,
                    (char *)&mtuflag, sizeof(mtuflag)) == SOCKET_ERROR) {
                sockerror(0, 0, 0, "Error disabling MTU discovery");
                closesocket(listener);
                exit(ERR_SOCKET);
            }
        }
#endif
        if (setsockopt(listener, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl,
                       sizeof(ttl)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting ttl");
            closesocket(listener);
            exit(ERR_SOCKET);
        }
#if (defined WINDOWS && _WIN32_WINNT < _WIN32_WINNT_LONGHORN) ||\
        (defined NO_DUAL)
    }
#endif
    if (rcvbuf) {
        if (setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
                       (char *)&rcvbuf, sizeof(rcvbuf)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting receive buffer size");
            exit(ERR_SOCKET);
        }
        if (setsockopt(listener, SOL_SOCKET, SO_SNDBUF,
                       (char *)&rcvbuf, sizeof(rcvbuf)) == SOCKET_ERROR) {
            sockerror(0, 0, 0, "Error setting send buffer size");
            exit(ERR_SOCKET);
        }
    } else {
        rcvbuf = DEF_RCVBUF;
        if (setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
                       (char *)&rcvbuf, sizeof(rcvbuf)) == SOCKET_ERROR) {
            rcvbuf = DEF_BSD_RCVBUF;
            if (setsockopt(listener, SOL_SOCKET, SO_RCVBUF,
                           (char *)&rcvbuf, sizeof(rcvbuf)) == SOCKET_ERROR) {
                sockerror(0, 0, 0, "Error setting receive buffer size");
                exit(ERR_SOCKET);
            }
        }
        rcvbuf = DEF_RCVBUF;
        if (setsockopt(listener, SOL_SOCKET, SO_SNDBUF,
                       (char *)&rcvbuf, sizeof(rcvbuf)) == SOCKET_ERROR) {
            rcvbuf = DEF_BSD_RCVBUF;
            if (setsockopt(listener, SOL_SOCKET, SO_SNDBUF,
                           (char *)&rcvbuf, sizeof(rcvbuf)) == SOCKET_ERROR) {
                sockerror(0, 0, 0, "Error setting send buffer size");
                exit(ERR_SOCKET);
            }
        }
    }

    for (i = 0; i < pub_multi_count; i++) {
        if (!multicast_join(listener, 0, &pub_multi[i], m_interface,
                            interface_count, server_fp, server_fp_count)) {
            exit(ERR_SOCKET);
        }
    }
}

/**
 * Initialization based on command line args
 */
void initialize(void)
{
    char hostname[256];
    struct addrinfo ai_hints, *ai_rval;
    int rval, i;

    parent = 0;

    // Load list of multicast interfaces
    if (interface_count == 0) {
        for (i = 0; i < ifl_len; i++) {
            if (!ifl[i].isloopback) {
                m_interface[interface_count++] = ifl[i];
            }
        }
    }
    // No non-loopback interfaces, so just use the hostname's interface
    if (interface_count == 0) {
        gethostname(hostname, sizeof(hostname));
        memset(&ai_hints, 0, sizeof(ai_hints));
        ai_hints.ai_family = AF_UNSPEC;
        ai_hints.ai_socktype = SOCK_DGRAM;
        ai_hints.ai_protocol = 0;
        ai_hints.ai_flags = 0;
        if ((rval = getaddrinfo(hostname, NULL, &ai_hints, &ai_rval)) != 0) {
            fprintf(stderr, "Can't get address of hostname %s: %s\n",
                    hostname, gai_strerror(rval));
            exit(ERR_PARAM);
        }
        memcpy(&m_interface[interface_count].su, ai_rval->ai_addr,
                ai_rval->ai_addrlen);
        m_interface[interface_count].ismulti = 1;
        m_interface[interface_count++].isloopback = 0;
        freeaddrinfo(ai_rval);
    }
    if (!uid) {
        if (m_interface[0].su.ss.ss_family == AF_INET6) {
            uid = m_interface[0].su.sin6.sin6_addr.s6_addr[12] << 24;
            uid |= m_interface[0].su.sin6.sin6_addr.s6_addr[13] << 16;
            uid |= m_interface[0].su.sin6.sin6_addr.s6_addr[14] << 8;
            uid |= m_interface[0].su.sin6.sin6_addr.s6_addr[15];
        } else {
            uid = m_interface[0].su.sin.sin_addr.s_addr;
        }
    }

    if (proxy_type == CLIENT_PROXY) {
        pub_multi_count = 0;
    } else if (!pub_multi_count) {
        memset(&ai_hints, 0, sizeof(ai_hints));
        ai_hints.ai_family = AF_UNSPEC;
        ai_hints.ai_socktype = SOCK_DGRAM;
        ai_hints.ai_protocol = 0;
        ai_hints.ai_flags = AI_NUMERICHOST;
        if ((rval = getaddrinfo(DEF_PUB_MULTI, out_portname,
                &ai_hints, &ai_rval)) != 0) {
            fprintf(stderr, "Can't get address of default public address: %s\n",
                    gai_strerror(rval));
            exit(ERR_PARAM);
        }
        memcpy(&pub_multi[0], ai_rval->ai_addr, ai_rval->ai_addrlen);
        freeaddrinfo(ai_rval);
        pub_multi_count = 1;
    }

    for (i = 0; i < MAXLIST; i++) {
        memset(&group_list[i], 0, sizeof(struct pr_group_list_t));
    }
    next_hb_time.tv_sec = 0;
    next_hb_time.tv_usec = 0;
    last_key_req.tv_sec = 0;
    last_key_req.tv_usec = 0;

    atexit(cleanup);
    key_init();
    create_sockets();

    daemonize();
    showtime = 1;
}

