/*
 * Copyright (C) 2018,2019 Huawei Technologies Duesseldorf GmbH
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
#include <keyutils.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <asm/unistd.h>

#include "compact_list.h"

#define DEFAULT_DIR "/etc/ima/digest_lists"
#define IMA_DIGEST_LIST_DATA_PATH IMA_SECURITYFS_PATH "/digest_list_data"

#define MOUNT_FLAGS MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME

static key_serial_t ima_keyring;


static int key_upload(int dirfd, char *key_filename)
{
	void *buf;
	loff_t size;
	int ret;

	if (!ima_keyring) {
		ima_keyring = syscall(__NR_add_key, "keyring", "_ima",
				NULL, 0, KEY_SPEC_USER_KEYRING);
		if (ima_keyring == -1)
			return -EPERM;
	}

	ret = read_file_from_path(dirfd, key_filename, &buf, &size);
	if (ret)
		return ret;

	return syscall(__NR_add_key, "asymmetric", NULL, buf, size,
		       ima_keyring);
}

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

static int digest_list_upload(int dirfd, int fd, struct list_head *head,
			      struct list_head *parser_lib_head,
			      char *digest_list_filename)
{
	char *list_id, *format_start, *format_end;
	struct lib *parser;
	void *buf;
	loff_t size;
	int ret;

	list_id = strchr(digest_list_filename, '-');
	if (!list_id++)
		return -EINVAL;

	format_start = strchr(list_id, '-');
	if (!format_start++)
		return -EINVAL;

	format_end = strchrnul(format_start, '-');
	if (!format_end)
		return -EINVAL;

	ret = read_file_from_path(dirfd, digest_list_filename, &buf, &size);
	if (ret)
		return ret;

	if (!strncmp(format_start, "compact", 7) && *format_end == '-') {
		if (fd >= 0) {
			ret = write_check(fd, buf, size);
		} else {
			ret = ima_parse_compact_list(size, buf, default_func);
			if (ret == size)
				ret = 0;
		}
		goto out;
	}

	parser = lookup_lib(parser_lib_head, "parser",
			    format_start, format_end - format_start);
	if (!parser) {
		printf("Cannot find a parser for %s\n", digest_list_filename);
		ret = -ENOENT;
		goto out;
	}

	ret = ((parser_func)parser->func)(fd, head, size, buf);
out:
	munmap(buf, size);
	return ret;
}

static void end_digest_list_upload(int umount_sysfs, int umount_securityfs)
{
	if (umount_securityfs)
		umount(SECURITYFS_PATH);
	if (umount_sysfs)
		umount(SYSFS_PATH);
}

static int process_lists(int dirfd, int fd, int save, struct list_head *head,
			 enum compact_types type)
{
	struct dirent **digest_lists;
	LIST_HEAD(parser_lib_head);
	int ret, i, n;

	n = scandirat(dirfd, ".", &digest_lists, filter[type], compare_lists);
	if (n == -1) {
		printf("Unable to access digest lists\n");
		return -EACCES;
	}

	for (i = 0; i < n; i++) {
		if (type == COMPACT_KEY) {
			if (save)
				continue;

			ret = key_upload(dirfd, digest_lists[i]->d_name);
			if (ret < 0) {
				printf("Unable to add key from %s\n",
				       digest_lists[i]->d_name);
			}

			continue;
		}

		ret = digest_list_upload(dirfd, fd, head, &parser_lib_head,
					 digest_lists[i]->d_name);
		if (ret)
			printf("Failed to process %s\n",
			       digest_lists[i]->d_name);
	}

	free_libs(&parser_lib_head);
	for (i = 0; i < n; i++)
		free(digest_lists[i]);

	free(digest_lists);
	return 0;
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <directory>: directory containing digest lists\n"
	       "\t-o <file>: write converted digest list to a file\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	int c, i, dirfd, fd = -1, ret = -EINVAL;
	int mount_sysfs = 0, mount_securityfs = 0;
	char *cur_dir = DEFAULT_DIR, *output = NULL;
	LIST_HEAD(list_head);

	while ((c = getopt(argc, argv, "d:o:h")) != -1) {
		switch (c) {
		case 'd':
			cur_dir = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return -EINVAL;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	dirfd = open(cur_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		printf("Unable to open %s, ret: %d\n", cur_dir, dirfd);
		return dirfd;
	}

	if (fd == -1) {
		if (!output)
			fd = init_digest_list_upload(&mount_sysfs,
						     &mount_securityfs);
		else
			fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (fd < 0) {
			ret = -EACCES;
			goto out_close_dirfd;
		}
	}

	for (i = 0; i < COMPACT__LAST; i++) {
		ret = process_lists(dirfd, fd, (output != NULL), &list_head, i);
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
	return ret;
}
