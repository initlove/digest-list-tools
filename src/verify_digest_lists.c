/*
 * Copyright (C) 2017-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: verify_digest_lists.c
 *      Verify digest lists.
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

#include "crypto.h"
#include "compact_list.h"

#define DEFAULT_DIR "/etc/ima/digest_lists"

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <directory>: directory containing digest lists\n"
	       "\t-f <filename>: filename in the digest list directory\n"
	       "\t-v: verbose mode\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	int c, i, dirfd, verbose = 0, ret = -EINVAL;
	char *cur_dir = DEFAULT_DIR;
	char *digest_list_filename = NULL;
	LIST_HEAD(key_head);

	while ((c = getopt(argc, argv, "d:f:vh")) != -1) {
		switch (c) {
		case 'd':
			cur_dir = optarg;
			break;
		case 'f':
			digest_list_filename = optarg;
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

	dirfd = open(cur_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		printf("Unable to open %s, ret: %d\n", cur_dir, dirfd);
		return dirfd;
	}

	for (i = 0; i < COMPACT__LAST; i++) {
		ret = process_lists(dirfd, -1, 0, verbose, &key_head, i,
				    PARSER_OP_VERIFY, cur_dir,
				    digest_list_filename);
		if (ret < 0)
			printf("Cannot access digest lists, ret: %d\n", ret);
	}

	free_keys(&key_head);
	close(dirfd);
	return ret;
}
