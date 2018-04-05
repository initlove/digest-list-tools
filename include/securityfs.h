/*
 * Copyright (C) 2017 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: securityfs.h
 *      Header of securityfs.c.
 */

#ifndef _SECURITYFS_H
#define _SECURITYFS_H

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "kernel_ima.h"

#define SYSFS_PATH "/sys"
#define SECURITYFS_PATH SYSFS_PATH "/kernel/security"
#define IMA_SECURITYFS_PATH SECURITYFS_PATH "/ima"
#define IMA_DIGEST_LIST_DATA_PATH IMA_SECURITYFS_PATH "/digest_list_data"
#define IMA_DIGEST_LIST_METADATA_PATH IMA_SECURITYFS_PATH \
				      "/digest_list_metadata"

#define MOUNT_FLAGS MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME

enum securityfs_files {DIGEST_LIST_METADATA, DIGEST_LIST_DATA};

extern int ima_fd;
extern int digests;
extern int sent_digests;
extern int digest_lists;

enum actions {ACTION_RESET, ACTION_ADD, ACTION_FLUSH};

int ima_add_digest_data_entry(u8 *digest, u16 digest_algo, u8 flags, u16 type,
			      enum actions action);
int ima_flush_digest_list_buffer(void);
int ima_init_upload(enum securityfs_files id);
void ima_end_upload(void);
int ima_upload_metadata(void *buf, loff_t size);

#endif /* _SECURITYFS_H */
