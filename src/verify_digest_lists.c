/*
 * Copyright (C) 2017-2019 Huawei Technologies Duesseldorf GmbH
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


static int process_lists(int dirfd, struct list_head *head,
			 enum compact_types type)
{
	struct dirent **digest_lists;
	struct key_struct *k;
	LIST_HEAD(parser_lib_head);
	int ret, i, n;

	n = scandirat(dirfd, ".", &digest_lists, filter[type], compare_lists);
	if (n == -1) {
		printf("Unable to access digest lists\n");
		return -EACCES;
	}

	for (i = 0; i < n; i++) {
		if (type == COMPACT_KEY) {
			k = new_key(head, dirfd, digest_lists[i]->d_name, NULL,
				    false);
			if (!k) {
				ret = -ENOMEM;
				goto out;
			}

			continue;
		}

		ret = verify_file(head, dirfd, digest_lists[i]->d_name);
		if (ret < 0)
			printf("Failed to process %s\n",
			       digest_lists[i]->d_name);
	}
out:
	free_keys(&parser_lib_head);
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
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	int c, i, dirfd, ret = -EINVAL;
	char *cur_dir = DEFAULT_DIR;
	LIST_HEAD(key_head);

	while ((c = getopt(argc, argv, "d:h")) != -1) {
		switch (c) {
		case 'd':
			cur_dir = optarg;
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
		ret = process_lists(dirfd, &key_head, i);
		if (ret < 0)
			printf("Cannot access digest lists, ret: %d\n", ret);
	}

	free_keys(&key_head);
	close(dirfd);
	return ret;
}
