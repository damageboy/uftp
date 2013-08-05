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

#ifdef WINDOWS

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>

#endif

#include "uftp_common.h"
#include "encryption.h"

void print_key(const char *name)
{
    union key_t key;
    int keytype;

    key = read_private_key(name, &keytype);
    if (keytype == KEYBLOB_RSA) {
        fprintf(stderr, "%s: RSA, %d bits, fingerprint: %s\n", name,
                RSA_keylen(key.rsa) * 8,
                print_key_fingerprint(key, KEYBLOB_RSA));
        free_RSA_key(key.rsa);
    } else if (keytype == KEYBLOB_EC) {
        fprintf(stderr, "%s: ECDSA, curve %s, fingerprint: %s\n", name,
                curve_name(get_EC_curve(key.ec)),
                print_key_fingerprint(key, KEYBLOB_EC));
        free_EC_key(key.ec);
    } else {
        fprintf(stderr, "%s: no such key\n", name);
    }
}

int main(int argc, char *argv[])
{
    union key_t key;
    int i, c;
    int gen_key_len, del_key, sys_key;
    uint8_t gen_key_curve;
    const char opts[] = "g:dm";

    log_level = 2;
    max_log_size = 0;
    init_log_mux = 0;
    applog = stderr;
    gen_key_len = 0;
    gen_key_curve = 0;
    del_key = 0;
    sys_key = 0;
    while ((c = getopt(argc, argv, opts)) != EOF) {
        switch (c) {
        case 'g':
            if (!strncmp("ec:", optarg, 3)) {
                gen_key_curve = get_curve(&optarg[3]);
                if (gen_key_curve == 0) {
                    fprintf(stderr, "Invalid curve");
                    exit(1);
                }
            } else if (!strncmp("rsa:", optarg, 4)) {
                gen_key_len = atoi(&optarg[4]);
                if ((gen_key_len < 512) || (gen_key_len > 2048)) {
                    fprintf(stderr, "Invalid key size\n");
                    exit(1);
                }
            } else {
                fprintf(stderr, "Invalid key specification\n");
                exit(1);
            }
            break;
        case 'd':
            del_key = 1;
            break;
        case 'm':
            sys_key = 1;
            break;
        }
    }
    argc -= optind;
    argv += optind;

    if (((gen_key_len != 0) || gen_key_curve != 0) && (del_key != 0)) {
        fprintf(stderr, "Can't specify both -g and -d\n");
        exit(1);
    }
    crypto_init(sys_key);

    key.key = 0;
    if (gen_key_len) {
        if (argc < 1) {
            fprintf(stderr, "No keyfile specified\n");
            exit(1);
        }
        key.rsa = gen_RSA_key(gen_key_len, RSA_EXP, argv[0]);
        if (key.key) {
            fprintf(stderr, "%s: RSA, %d bits, fingerprint: %s\n", argv[0],
                    RSA_keylen(key.rsa) * 8,
                    print_key_fingerprint(key, KEYBLOB_RSA));
            free_RSA_key(key.rsa);
        } else {
            fprintf(stderr, "Error generating/storing key\n");
        }
    } else if (gen_key_curve) {
        if (argc < 1) {
            fprintf(stderr, "No keyfile specified\n");
            exit(1);
        }
        key.ec = gen_EC_key(gen_key_curve, 0, argv[0]);
        if (key.key) {
            fprintf(stderr, "%s: ECDSA, curve %s, fingerprint: %s\n", argv[0],
                    curve_name(get_EC_curve(key.ec)),
                    print_key_fingerprint(key, KEYBLOB_EC));
            free_EC_key(key.ec);
        } else {
            fprintf(stderr, "Error generating/storing key\n");
        }
    } else if (del_key) {
        if (argc < 1) {
            fprintf(stderr, "No keyfile specified\n");
            exit(1);
        }
        delete_container(argv[0]);
    } else {
        for (i = 0; i < argc; i++) {
            print_key(argv[i]);
        }
#if defined WINDOWS && !defined OPENSSL
        if (argc == 0) {
            const char *name;
            while ((name = get_next_container()) != NULL) {
                print_key(name);
            }
        }
#endif
    }
    crypto_cleanup();
    return 0;
}
