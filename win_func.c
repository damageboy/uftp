/*
 *  UFTP - UDP based FTP with multicast
 *
 *  Copyright (C) 2001-2011   Dennis A. Bush, Jr.   bush@tcnj.edu
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

#include <string.h>
#include <ctype.h>
#include <windows.h>

#include "win_func.h"

int optind=1;
char *optarg;

char getopt(int argc, char *argv[], const char options[])
{
    char *loc;

    if (optind >= argc) {
        return -1;
    } else if (strlen(argv[optind]) <= 1) {
        return -1;
    } else if (argv[optind][0] != '-') {
        return -1;
    } else if (argv[optind][1] == '-') {
        optind++;
        return -1;
    } else if (!isalnum(argv[optind][1])) {
        return '?';
    } else if ((loc = strchr(options, argv[optind][1])) == NULL) {
        return '?';
    } else {
        optind++;
        if (loc[1] == ':') {
            optarg = argv[optind++];
        }
        return loc[0];
    }
}

int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    const unsigned __int64 epoch_diff = 11644473600000000;
    unsigned __int64 tmp;
    FILETIME t;

    if (tv) {
        GetSystemTimeAsFileTime(&t);
 
        tmp = 0;
        tmp |= t.dwHighDateTime;
        tmp <<= 32;
        tmp |= t.dwLowDateTime;
 
        tmp /= 10;
        tmp -= epoch_diff;
        tv->tv_sec = (long)(tmp / 1000000);
        tv->tv_usec = (long)(tmp % 1000000);
    }

    return 0;
}

int get_win_priority(int priority)
{
    switch (priority) {
    case -2:
        return HIGH_PRIORITY_CLASS;
    case -1:
        return ABOVE_NORMAL_PRIORITY_CLASS;
    case 0:
        return NORMAL_PRIORITY_CLASS;
    case 1:
        return BELOW_NORMAL_PRIORITY_CLASS;
    case 2:
        return IDLE_PRIORITY_CLASS;
    default:
        return NORMAL_PRIORITY_CLASS;
    }
}