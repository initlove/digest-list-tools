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
 * File: copy.c
 *      Copy existing file to a digest list directory.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#include "lib.h"
#include "compact_list.h"


int generator(int dirfd, int pos, struct list_head *head_in,
	      struct list_head *head_out, enum compact_types type,
	      u16 modifiers, enum hash_algo algo)
{
	struct path_struct *cur;
	char filename[NAME_MAX + 1];
	char *basename;
	void *buf;
	loff_t size;
	int ret = 0, fd;

	if (list_empty(head_in)) {
		printf("Input path not specified\n");
		return -EINVAL;
	}

	list_for_each_entry(cur, head_in, list) {
		basename = strrchr(cur->path, '/');
		if (!basename)
			basename = cur->path;
		else
			basename++;

		snprintf(filename, sizeof(filename), "%d-%s_list-%s", pos,
			 compact_types_str[type], basename);

		ret = read_file_from_path(-1, cur->path, &buf, &size);
		if (ret < 0)
			goto out;

		fd = openat(dirfd, filename, O_WRONLY | O_CREAT, 0600);
		if (fd < 0) {
			munmap(buf, size);
			ret = fd;
			goto out;
		}

		ret = write_check(fd, buf, size);
		munmap(buf, size);
		close(fd);

		if (ret < 0)
			goto out;

		ret = add_path_struct(filename, head_out);
		if (ret < 0)
			goto out;

		pos++;
	}
out:
	if (ret < 0)
		unlinkat(dirfd, filename, 0);

	return ret;
}
