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
#include <errno.h>

#ifdef WINDOWS

#include <ws2tcpip.h>
#include <io.h>
#include <direct.h>

#include "win_func.h"

#else  // if WINDOWS

#include <unistd.h>

#endif

#include "client.h"
#include "client_common.h"
#include "client_fileinfo.h"
#include "client_transfer.h"

/**
 * Send a COMPLETE with the given status in response to a FILEINFO,
 * set the phase to MIDGROUP, and reset the timeout
 */
void early_complete(struct group_list_t *group, int status, int freespace)
{
    group->phase = PHASE_MIDGROUP;
    group->fileinfo.comp_status = status;
    send_complete(group, freespace);
    print_result_status(group);
    set_timeout(group, 0);
}

/**
 * Read in the contents of a FILEINFO message
 * Returns 1 on success, 0 on error or ignore
 */
int read_fileinfo(struct group_list_t *group, const unsigned char *message,
                  int meslen, struct timeval rxtime)
{
    const struct fileinfo_h *fileinfo;
    const uint32_t *addrlist;
    int listlen, maxsecsize;
    const char *name, *flink, *p;

    fileinfo = (const struct fileinfo_h *)message;
    addrlist = (const uint32_t *)(message + (fileinfo->hlen * 4));
    name = (const char *)message + sizeof(struct fileinfo_h);
    flink = name + (fileinfo->namelen * 4);
    listlen = (meslen - (fileinfo->hlen * 4)) / 4;

    if ((meslen < (fileinfo->hlen * 4)) ||
            ((fileinfo->hlen * 4) < sizeof(struct fileinfo_h)) ||
            ((fileinfo->namelen * 4) > MAXPATHNAME) ||
            ((fileinfo->linklen * 4) > MAXPATHNAME) ||
            ((fileinfo->hlen * 4) != sizeof(struct fileinfo_h) +
                (fileinfo->namelen * 4) + (fileinfo->linklen * 4))) {
        glog1(group, "Rejecting FILEINFO from server: invalid message size");
        send_abort(group, "Rejecting FILEINFO: invalid message size");
        return 0;
    }
    if (!uid_in_list(addrlist, listlen)) {
        set_timeout(group, 0);
        return 0;
    }

    if (group->phase == PHASE_RECEIVING) {
        // We already got the FILEINFO, so no need to reprocess.
        // Just resend the INFO_ACK and reset the timeout
        send_fileinfo_ack(group, group->fileinfo.restart);
        set_timeout(group, 0);
        return 0;
    }
    if ((group->phase == PHASE_MIDGROUP) &&
            (group->file_id == ntohs(fileinfo->file_id))) {
        // We already got the FILEINFO, and it's for a completed file.
        // So resend the COMPLETE and reset the timeout
        send_complete(group, (fileinfo->ftype == FTYPE_FREESPACE));
        set_timeout(group, 0);
        return 0;
    }

    // Load fileinfo params into list
    memset(&group->fileinfo, 0, sizeof(struct file_t));
    group->fileinfo.ftype = fileinfo->ftype;
    group->file_id = ntohs(fileinfo->file_id);
    strncpy(group->fileinfo.name, name, fileinfo->namelen * 4);
    strncpy(group->fileinfo.linkname, flink, fileinfo->linklen * 4);
    group->fileinfo.size = (f_offset_t)ntohs(fileinfo->hifsize) << 32;
    group->fileinfo.size |= ntohl(fileinfo->lofsize);

    if (group->fileinfo.size) {
        maxsecsize = (group->blocksize * 8 > MAXSECTION ?
                MAXSECTION : group->blocksize * 8);
        group->fileinfo.blocks =
                (int32_t)((group->fileinfo.size / group->blocksize) +
                (group->fileinfo.size % group->blocksize ? 1 : 0));
        group->fileinfo.sections = (group->fileinfo.blocks / maxsecsize) +
                (group->fileinfo.blocks % maxsecsize ? 1 : 0);
        group->fileinfo.secsize_small =
                group->fileinfo.blocks / group->fileinfo.sections;
        group->fileinfo.secsize_big = group->fileinfo.secsize_small +
                (group->fileinfo.blocks % group->fileinfo.sections ? 1 : 0);
        group->fileinfo.big_sections = group->fileinfo.blocks -
                (group->fileinfo.secsize_small * group->fileinfo.sections);
    } else {
        group->fileinfo.blocks = 0;
        group->fileinfo.sections = 0;
        group->fileinfo.secsize_small = 0;
        group->fileinfo.secsize_big = 0;
        group->fileinfo.big_sections = 0;
    }

    group->fileinfo.tstamp = ntohl(fileinfo->ftstamp);
    group->last_server_ts.tv_sec = ntohl(fileinfo->tstamp_sec);
    group->last_server_ts.tv_usec = ntohl(fileinfo->tstamp_usec);
    group->last_server_rx_ts = rxtime;
    group->fileinfo.fd = -1;

    // Run some checks on the filename
    if (strlen(group->fileinfo.name) == 0) {
        glog1(group, "Rejecting FILEINFO from server: blank file name");
        early_complete(group, COMP_STAT_REJECTED, 0);
        return 0;
    }
    p = strstr(group->fileinfo.name, "..");
    if ((p != NULL) && ((p[2] == '\x0') || (p[2] == '/') || (p[2] == '\\')) &&
           ((p == group->fileinfo.name) || (p[-1] == '/') || (p[-1] == '\\'))) {
        glog1(group, "Rejecting FILEINFO from server: filename contains ..");
        early_complete(group, COMP_STAT_REJECTED, 0);
        return 0;
    }
    if (fileinfo->ftype == FTYPE_LINK) {
        if (strlen(group->fileinfo.linkname) == 0) {
            glog1(group, "Rejecting FILEINFO from server: blank link name");
            early_complete(group, COMP_STAT_REJECTED, 0);
            return 0;
        }
    }

    return 1;
}

/**
 * Validate and establish the destination name of an incoming file.
 * Returns 0 if the file was rejected for some reason, 1 otherwise.
 */
int setup_dest_file(struct group_list_t *group)
{
    int found_dest_dir, len, i;
    int (*cmp)(const char *, const char *);
    int (*ncmp)(const char *, const char *, size_t);

#if PATH_SEP != '/'
    // First translate any '/' in the sent file name to PATH_SEP
    {
        char *p;
        while ((p = strchr(group->fileinfo.name, '/')) != NULL) {
            *p = PATH_SEP;
        }
    }
#endif

#ifdef WINDOWS
    cmp = stricmp;
    ncmp = strnicmp;
#else
    cmp = strcmp;
    ncmp = strncmp;
#endif

    if (isfullpath(group->fileinfo.name)) {
        if (strcmp(tempdir, "")) {
            glog1(group, "Rejecting file with absolute pathname: "
                         "temp directory is in use");
            early_complete(group, COMP_STAT_REJECTED, 0);
            return 0;
        }
        for (found_dest_dir = 0, i = 0; i < destdircnt; i++) {
            if (!ncmp(group->fileinfo.name, destdir[i], strlen(destdir[i]))) {
                if (!cmp(group->fileinfo.name, destdir[i])) {
                    glog1(group, "Rejecting file with absolute pathname: "
                                "can't have the same name as a dest directory");
                    early_complete(group, COMP_STAT_REJECTED, 0);
                    return 0;
                } else {
                    found_dest_dir = 1;
                    break;
                }
            }
        }
        if (!found_dest_dir) {
            glog1(group, "Rejecting file with absolute pathname: "
                         "doesn't match any dest directory");
            early_complete(group, COMP_STAT_REJECTED, 0);
            return 0;
        }
        group->fileinfo.destdiridx = i;
        snprintf(group->fileinfo.filepath,
            sizeof(group->fileinfo.filepath), "%s", group->fileinfo.name);
    } else {
        if (!strcmp(tempdir, "")) {
            len = snprintf(group->fileinfo.filepath,
                    sizeof(group->fileinfo.filepath), "%s%c%s",
                    destdir[0], PATH_SEP, group->fileinfo.name);
        } else {
            len = snprintf(group->fileinfo.filepath,
                    sizeof(group->fileinfo.filepath),
                    "%s%c_group_%08X%c%s", tempdir, PATH_SEP, group->group_id,
                    PATH_SEP, group->fileinfo.name);
        }
        if (len >= sizeof(group->fileinfo.filepath)) {
            glog1(group, "Rejecting file: max pathname length exceeded");
            early_complete(group, COMP_STAT_REJECTED, 0);
            return 0;
        }

    }
    len = snprintf(group->fileinfo.temppath, sizeof(group->fileinfo.temppath),
                   "%s.~uftp-%08X-%04X", group->fileinfo.filepath,
                   group->group_id, group->file_id);
    if (len >= sizeof(group->fileinfo.temppath)) {
        glog1(group, "Rejecting file: max pathname length exceeded");
        early_complete(group, COMP_STAT_REJECTED, 0);
        return 0;
    }
    return 1;
}

/**
 * Perform FILEINFO processing specific to a regular file in restart mode
 * Returns 1 if a COMPLETE was sent in response, 0 otherwise
 */
int handle_fileinfo_restart(struct group_list_t *group)
{
    stat_struct statbuf;

    if ((!strcmp(group->fileinfo.name, group->restartinfo->name)) &&
            (group->fileinfo.size == group->restartinfo->size) &&
            (group->fileinfo.blocks == group->restartinfo->blocks) &&
            (group->fileinfo.sections == group->restartinfo->sections)) {
        // Flag this file to restart a failed transfer
        group->fileinfo.restart = 1;
        return 0;
    } else if ((lstat_func(group->fileinfo.filepath, &statbuf) != -1) &&
               S_ISREG(statbuf.st_mode) &&
               (statbuf.st_size == group->fileinfo.size)) {
        // This file was finished on the last attempt,
        // so respond with a COMPLETE right away
        early_complete(group, COMP_STAT_NORMAL, 0);
        return 1;
    }
    return 0;
}

/**
 * Perform FILEINFO processing specific to a regular file in sync mode
 * Returns 1 if a COMPLETE was sent in response, 0 otherwise
 */
int handle_fileinfo_sync(struct group_list_t *group)
{
    stat_struct statbuf;

    if (lstat_func(group->fileinfo.filepath, &statbuf) != -1) {
        // If source is newer, skip
        // If source is older, overwrite
        // If timestamps same, skip if sizes are also same
        int skip;
        if (group->fileinfo.tstamp < statbuf.st_mtime) {
            skip = 1;
        } else if (group->fileinfo.tstamp > statbuf.st_mtime) {
            skip = 0;
        } else if (S_ISREG(statbuf.st_mode) &&
                   (statbuf.st_size == group->fileinfo.size)) {
            skip = 1;
        } else {
            skip = 0;
        }
        if (skip) {
            glog2(group, "skipping file, in sync");
            early_complete(group, COMP_STAT_SKIPPED, 0);
            return 1;
        } else {
            glog2(group, "overwriting out of sync file");
            group->fileinfo.comp_status = COMP_STAT_OVERWRITE;
            if (group->sync_preview) {
                glog2(group, "Sync preview mode, skipping receive");
                early_complete(group, COMP_STAT_OVERWRITE, 0);
                return 1;
            }
            if (!tempfile) {
                move_to_backup(group);
            }
        }
    } else {
        glog2(group, "copying new file");
        if (group->sync_preview) {
            glog2(group, "Sync preview mode, skipping receive");
            early_complete(group, COMP_STAT_NORMAL, 0);
            return 1;
        }
        if (!tempfile) {
            move_to_backup(group);
        }
    }
    return 0;
}

/**
 * Perform FILEINFO processing specific to a regular file
 */
void handle_fileinfo_regular(struct group_list_t *group)
{
    // First handle restart or sync mode,
    // then create/open the file.
    if (group->restartinfo) {
        if (handle_fileinfo_restart(group)) {
            return;
        }
    } else if (group->sync_mode) {
        if (handle_fileinfo_sync(group)) {
            return;
        }
    }
    if (group->fileinfo.restart) {
        group->fileinfo.fd = open(group->fileinfo.filepath, OPENWRITE);
    } else {
        const char *filename;
        if (tempfile) {
            filename = group->fileinfo.temppath;
        } else {
            filename = group->fileinfo.filepath;
        }
#ifdef WINDOWS
        SetFileAttributes(filename, FILE_ATTRIBUTE_NORMAL);
#else
        chmod(filename, 0644);
#endif
        group->fileinfo.fd = open(filename, OPENWRITE | O_CREAT | O_TRUNC,0644);
    }
    if (group->fileinfo.fd == -1) {
        gsyserror(group, "Error opening data file");
        early_complete(group, COMP_STAT_REJECTED, 0);
        return;
    }
    if (group->fileinfo.size > free_space(group->fileinfo.filepath)) {
        glog0(group, "Not enough disk space, aborting");
        send_abort(group, "Not enough disk space");
        return;
    }

    // Final preparations for receiving a file.
    if (group->fileinfo.restart) {
        group->fileinfo.naklist = group->restartinfo->naklist;
        group->fileinfo.section_done = group->restartinfo->section_done;
        group->restartinfo->naklist = NULL;
        group->restartinfo->section_done = NULL;
        free(group->restartinfo);
        group->restartinfo = NULL;
    } else {
        group->fileinfo.naklist = safe_calloc(group->fileinfo.blocks, 1);
        group->fileinfo.section_done = safe_calloc(group->fileinfo.sections, 1);
        memset(group->fileinfo.naklist, 1, group->fileinfo.blocks);
    }
    group->fileinfo.last_block = -1;
    group->fileinfo.last_section = 0;
    group->fileinfo.curr_offset = 0;
    group->fileinfo.cache_start = 0;
    group->fileinfo.cache_end = 0;
    group->fileinfo.cache_len = 0;
    group->fileinfo.cache = safe_calloc(cache_len, 1);
    group->fileinfo.cache_status = safe_calloc(cache_len / group->blocksize, 1);
    group->phase = PHASE_RECEIVING;
    send_fileinfo_ack(group, group->fileinfo.restart);
    set_timeout(group, 0);
}

/**
 * Perform FILEINFO processing specific to an empty directory
 */
void handle_fileinfo_dir(struct group_list_t *group, int found_dir)
{
    if (!found_dir && !group->sync_preview) {
        glog2(group, "Creating directory");
        if (mkdir(group->fileinfo.filepath, 0755) == -1) {
            gsyserror(group, "Failed to create directory %s",
                             group->fileinfo.filepath);
            early_complete(group, COMP_STAT_REJECTED, 0);
            return;
        }
    }
    early_complete(group, found_dir ? COMP_STAT_SKIPPED : COMP_STAT_NORMAL, 0);
}

/**
 * Perform FILEINFO processing specific to a symbolic link
 */
void handle_fileinfo_link(struct group_list_t *group)
{
#ifndef WINDOWS
    if (!group->sync_preview) {
        if (symlink(group->fileinfo.linkname, group->fileinfo.filepath) == -1) {
            gsyserror(group, "Failed to create symlink %s",
                             group->fileinfo.filepath);
            early_complete(group, COMP_STAT_REJECTED, 0);
            return;
        }
    }
#endif
    early_complete(group, COMP_STAT_NORMAL, 0);
}

/**
 * Perform FILEINFO processing specific to a delete command
 */
void handle_fileinfo_delete(struct group_list_t *group)
{
    if (!group->sync_preview) {
        move_to_backup(group);
    }
    early_complete(group, COMP_STAT_NORMAL, 0);
}

/**
 * Perform FILEINFO processing specific to a freespace command
 */
void handle_fileinfo_freespace(struct group_list_t *group)
{
    early_complete(group, COMP_STAT_NORMAL, 1);
}

/**
 * Process an incoming FILEINFO message.
 * Expected in the middle of a group with no current file.
 */
void handle_fileinfo(struct group_list_t *group, const unsigned char *message,
                     unsigned meslen, struct timeval rxtime)
{
    stat_struct statbuf;
    int found_dir;

    if (!read_fileinfo(group, message, meslen, rxtime)) {
        return;
    }

    glog2(group, "Name of file to receive: %s", group->fileinfo.name);
    switch (group->fileinfo.ftype) {
    case FTYPE_REG:
        glog2(group, "Bytes: %s, Blocks: %d, Sections: %d",
                     printll(group->fileinfo.size),
                     group->fileinfo.blocks, group->fileinfo.sections);
        glog3(group, "small section size: %d, "
                     "big section size: %d, # big sections: %d",
                     group->fileinfo.secsize_small, group->fileinfo.secsize_big,
                     group->fileinfo.big_sections);
        break;
    case FTYPE_DIR:
        glog2(group, "Empty directory");
        break;
    case FTYPE_LINK:
        glog2(group, "Symbolic link to %s", group->fileinfo.linkname);
        break;
    case FTYPE_DELETE:
        glog2(group, "Deleting file/directory");
        break;
    case FTYPE_FREESPACE:
        glog2(group, "Get free space for path");
        break;
    default:
        glog1(group, "Invalid file type: %d", group->fileinfo.ftype);
        send_abort(group, "Invalid file type");
        return;
    }

    if (!setup_dest_file(group)) {
        // A rejected file is still a success because we responded with a
        // COMPLETE with status=rejected instead of with an ABORT
        return;
    }

    // Make sure the path to the destination file exists and
    // remove or back up any existing file
    if (!create_path_to_file(group, group->fileinfo.filepath)) {
        glog0(group, "Error creating path to data file");
        early_complete(group, COMP_STAT_REJECTED, 0);
        return;
    }
    found_dir = 0;
    if (tempfile && !group->sync_preview) {
        clear_path(group->fileinfo.temppath, group);
    }
    if ((group->fileinfo.ftype != FTYPE_DELETE) ||
            (group->fileinfo.ftype != FTYPE_FREESPACE)) {
        // Don't do path checks for metafile commands
    } else if (lstat_func(group->fileinfo.filepath, &statbuf) != -1) {
        glog3(group, "checking existing file");
        if ((group->fileinfo.ftype != FTYPE_DIR) || !S_ISDIR(statbuf.st_mode)) {
            if ((group->fileinfo.ftype != FTYPE_REG) ||
                    !S_ISREG(statbuf.st_mode) ||
                    ((!group->restart) && (!group->sync_mode))) {
                // Don't clear/backup if we're receiving a regular file
                // and we're in either restart mode or sync mode
                glog3(group, "calling move_to_backup");
                if (!tempfile) {
                    move_to_backup(group);
                }
            }
        } else {
            glog3(group, "found dir");
            found_dir = 1;
        }
    } else if (errno != ENOENT) {
        gsyserror(group, "Error checking file %s",group->fileinfo.filepath);
    }

    switch (group->fileinfo.ftype) {
    case FTYPE_REG:
        handle_fileinfo_regular(group);
        break;
    case FTYPE_DIR:
        handle_fileinfo_dir(group, found_dir);
        break;
    case FTYPE_LINK:
        handle_fileinfo_link(group);
        break;
    case FTYPE_DELETE:
        handle_fileinfo_delete(group);
        break;
    case FTYPE_FREESPACE:
        handle_fileinfo_freespace(group);
        break;
    default:
        glog0(group, "Error handling FILEINFO: shouldn't get here!");
    }
}
