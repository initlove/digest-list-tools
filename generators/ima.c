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
 * File: ima.c
 *      Generates IMA digest lists.
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "compact_list.h"

#define IMA_ASCII_PATH IMA_SECURITYFS_PATH "/ascii_runtime_measurements"
#define IMA_ASCII_FORMAT "ima+ima_ng"


int ima_ng_generator(int dirfd, int pos, struct list_head *head_in,
		     struct list_head *head_out, enum compact_types type,
		     u16 modifiers, enum hash_algo algo)
{
	char filename[NAME_MAX + 1], buffer[1024];
	time_t t = time(NULL);
	struct path_struct *cur;
	struct tm tm;
	size_t size;
	int ret, i, fd_in, fd_out, prefix_len;

	if (list_empty(head_in)) {
		ret = add_path_struct(IMA_ASCII_PATH, head_in);
		if (ret < 0)
			return ret;
	}

	tm = *localtime(&t);

	prefix_len = gen_filename_prefix(filename, sizeof(filename), pos,
					 IMA_ASCII_FORMAT, type);
	snprintf(filename + prefix_len, sizeof(filename) - prefix_len,
		 "%04d%02d%02d_%02d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1,
		 tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	fd_out = openat(dirfd, filename, O_CREAT | O_WRONLY, 0600);
	if (fd_out < 0) {
		printf("Cannot open %s\n", filename);
		return fd_out;
	}

	for (i = 0; i < sizeof(modifiers) * 8; i++) {
		if (!(modifiers & (1 << i)))
			continue;

		if (i) {
			ret = write_check(fd_out, " ", 1);
			if (ret < 0)
				goto out;
		}

		ret = write_check(fd_out, compact_modifiers_str[i],
				  strlen(compact_modifiers_str[i]));
		if (ret < 0)
			goto out;
	}

	ret = write_check(fd_out, "\n", 1);
	if (ret < 0)
		goto out;

	list_for_each_entry(cur, head_in, list) {
		fd_in = open(cur->path, O_RDONLY);
		if (fd_in < 0) {
			printf("Cannot open %s\n", IMA_ASCII_PATH);
			goto out;
		}

		while ((size = read(fd_in, buffer, sizeof(buffer))) > 0) {
			ret = write_check(fd_out, buffer, size);
			if (ret < 0) {
				close(fd_in);
				goto out;
			}
		}

		close(fd_in);
	}

	ret = add_path_struct(filename, head_out);
	if (ret < 0)
		goto out;
out:
	close(fd_out);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);

	return ret;
}
