/*
 * Copyright (C) 2018-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: upload_digest_lists.c
 *      Parse and upload digest lists
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <linux/magic.h>

#include "compact_list.h"
#include "ima_list.h"
#include "selinux.h"

#define DEFAULT_DIR "/etc/ima/digest_lists"
#define IMA_DIGEST_LIST_DATA_PATH IMA_SECURITYFS_PATH "/digest_list_data"

#define MOUNT_FLAGS MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME

static int init_digest_list_upload(int *mount_sysfs, int *mount_securityfs)
{
	struct stat st;
	int ret, fd;

	if (!stat(IMA_DIGEST_LIST_DATA_PATH, &st))
		goto out;

	if (!stat(SECURITYFS_PATH, &st))
		goto mount_securityfs;

	ret = mount(SYSFS_PATH, SYSFS_PATH, "sysfs", MOUNT_FLAGS, NULL);
	if (ret < 0) {
		printf("Cannot mount %s (%s)\n", SYSFS_PATH,
		       strerror(errno));
		return ret;
	}

	*mount_sysfs = 1;
mount_securityfs:
	ret = mount(SECURITYFS_PATH, SECURITYFS_PATH, "securityfs", MOUNT_FLAGS,
		    NULL);
	if (ret < 0) {
		printf("Cannot mount %s (%s)\n", SECURITYFS_PATH,
		       strerror(errno));
		return ret;
	}

	*mount_securityfs = 1;
out:
	fd = open(IMA_DIGEST_LIST_DATA_PATH, O_WRONLY);
	if (fd < 0) {
		printf("Cannot open %s\n", IMA_DIGEST_LIST_DATA_PATH);
		return -EACCES;
	}

	return fd;
}

static void end_digest_list_upload(int umount_sysfs, int umount_securityfs)
{
	if (umount_securityfs)
		umount(SECURITYFS_PATH);
	if (umount_sysfs)
		umount(SYSFS_PATH);
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-b <backup_dir>: specify backup dir\n"
	       "\t-d <directory>: directory containing digest lists\n"
	       "\t-f <filename>: filename in the digest list directory\n"
	       "\t-o <file>: write converted digest list to a file\n"
	       "\t-p <op>: specify parser operation:\n"
	       "\t\tadd-digest: add IMA digest to kernel/output file\n"
	       "\t\tadd-meta-digest: add EVM digest to kernel/output file\n"
	       "\t\tadd-ima-xattr: set IMA xattr for files in the digest lists\n"
	       "\t\trm-ima-xattr: remove IMA xattr for files in the digest lists\n"
	       "\t\tadd-evm-xattr: set EVM xattr for files in the digest lists\n"
	       "\t\trm-evm-xattr: remove EVM xattr for files in the digest lists\n"
	       "\t\trm-infoflow-xattr: remove Infoflow xattr for files in the digest lists\n"
	       "\t\tdump: display content of digest lists\n"
	       "\t\tgen-ima-list: generate IMA digest list with digest list measurement\n"
	       "\t\tcheck-meta: compare metadata between digest lists and filesystem\n"
	       "\t\trepair-meta: set metadata from the digest lists to the filesystem\n"
	       "\t-v: verbose mode\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	int c, i, dirfd, fd = -1, verbose = 0, ret = -EINVAL;
	int mount_sysfs = 0, mount_securityfs = 0;
	char *cur_dir = DEFAULT_DIR, *output = NULL, *backup_dir = NULL;
	enum parser_ops op = PARSER_OP_ADD_DIGEST;
	char *digest_list_filename = NULL;
	LIST_HEAD(list_head);

	while ((c = getopt(argc, argv, "b:d:o:p:f:vh")) != -1) {
		switch (c) {
		case 'b':
			backup_dir = optarg;
			break;
		case 'd':
			cur_dir = optarg;
			break;
		case 'f':
			digest_list_filename = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'p':
			if (!strcmp(optarg, "add-digest")) {
				op = PARSER_OP_ADD_DIGEST;
			} else if (!strcmp(optarg, "update-digest")) {
				op = PARSER_OP_UPDATE_DIGEST;
				fd = -2;
			} else if (!strcmp(optarg, "restore-files")) {
				op = PARSER_OP_RESTORE_FILES;
				fd = -2;
			} else if (!strcmp(optarg, "add-meta-digest")) {
				op = PARSER_OP_ADD_META_DIGEST;
			} else if (!strcmp(optarg, "add-ima-xattr")) {
				op = PARSER_OP_ADD_IMA_XATTR;
				fd = -2;
			} else if (!strcmp(optarg, "rm-ima-xattr")) {
				op = PARSER_OP_REMOVE_IMA_XATTR;
				fd = -2;
			} else if (!strcmp(optarg, "add-evm-xattr")) {
				op = PARSER_OP_ADD_EVM_XATTR;
				fd = -2;
			} else if (!strcmp(optarg, "rm-evm-xattr")) {
				op = PARSER_OP_REMOVE_EVM_XATTR;
				fd = -2;
			} else if (!strcmp(optarg, "rm-infoflow-xattr")) {
				op = PARSER_OP_REMOVE_INFOFLOW_XATTR;
				fd = -2;
			} else if (!strcmp(optarg, "dump")) {
				op = PARSER_OP_DUMP;
				fd = -2;
			} else if (!strcmp(optarg, "gen-ima-list")) {
				op = PARSER_OP_GEN_IMA_LIST;
			} else if (!strcmp(optarg, "check-meta")) {
				op = PARSER_OP_CHECK_META;
				fd = -2;
			} else if (!strcmp(optarg, "repair-meta")) {
				op = PARSER_OP_REPAIR_META;
				fd = -2;
			} else {
				printf("Invalid parser op %s\n", optarg);
				return 1;
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			return -EINVAL;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	if (op == PARSER_OP_UPDATE_DIGEST && output) {
		printf("Output file cannot be specified for "
		       "update-digest op\n");
		return -EINVAL;
	}

	if (op == PARSER_OP_UPDATE_DIGEST && !backup_dir) {
		printf("Backup dir not specified for update-digest op\n");
		return -EINVAL;
	}

	dirfd = open(cur_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		printf("Unable to open %s, ret: %d\n", cur_dir, dirfd);
		goto out;
	}

	if (fd == -1) {
		if (!output)
			fd = init_digest_list_upload(&mount_sysfs,
						     &mount_securityfs);
		else
			fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (fd < 0) {
			ret = -EACCES;
			goto out_close_dirfd;
		}
	}

	if (op == PARSER_OP_GEN_IMA_LIST) {
		ret = ima_copy_boot_aggregate(fd);
		if (ret < 0)
			return ret;

		ret = ima_generate_entry(-1, fd, "", IMA_KEY_PATH);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < COMPACT__LAST; i++) {
		ret = process_lists(dirfd, fd, (output != NULL), verbose,
				    &list_head, i, op, backup_dir, cur_dir,
				    digest_list_filename);
		if (ret < 0) {
			printf("Cannot upload digest lists, ret: %d\n", ret);
			goto out_close_fd;
		}

		ret = compact_list_flush_all(fd, &list_head);
		if (ret < 0) {
			printf("Cannot upload digest lists, ret: %d\n", ret);
			goto out_close_fd;
		}
	}
out_close_fd:
	if (fd >= 0)
		close(fd);

	end_digest_list_upload(mount_sysfs, mount_securityfs);
out_close_dirfd:
	close(dirfd);
out:
	if (op == PARSER_OP_ADD_META_DIGEST)
		selinux_end_setup();

	return ret;
}
