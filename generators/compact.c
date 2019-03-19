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
 * File: compact.c
 *      Generates compact digest lists.
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "compact_list.h"
#include "crypto.h"
#include "xattr.h"

#define FORMAT "compact"


int generator(int dirfd, int pos, struct list_head *head_in,
	      struct list_head *head_out, enum compact_types type,
	      u16 modifiers, enum hash_algo algo)
{
	struct path_struct *cur;
	u8 digest[SHA512_DIGEST_SIZE];
	char filename[NAME_MAX + 1], *basename, *link, *target;
	LIST_HEAD(list_head);
	struct list_struct *list;
	struct stat st;
	int ret = 0, fd, prefix_len;

	if (list_empty(head_in)) {
		printf("Input path not specified\n");
		return -EINVAL;
	}

	cur = list_first_entry(head_in, struct path_struct, list);

	basename = strrchr(cur->path, '/');
	if (!basename)
		basename = cur->path;
	else
		basename++;

	prefix_len = gen_filename_prefix(filename, sizeof(filename), pos,
					 FORMAT, type);
	snprintf(filename + prefix_len, sizeof(filename) - prefix_len, "%s",
		 basename);

	fd = openat(dirfd, filename, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		printf("Cannot open %s\n", filename);
		return fd;
	}

	list = compact_list_init(&list_head, type, modifiers, algo);
	if (!list)
		goto out;

	list_for_each_entry(cur, head_in, list) {
		if (lstat(cur->path, &st) == -1)
			continue;

		if (S_ISLNK(st.st_mode)) {
			target = realpath(cur->path, NULL);
			if (ret < 0)
				goto out;

			free(cur->path);
			cur->path = target;
		}

		ret = calc_file_digest(digest, -1, cur->path, algo);
		if (ret < 0) {
			printf("Cannot calculate digest of %s\n", cur->path);
			goto out_free;
		}

		ret = compact_list_add_digest(fd, list, digest);
		if (ret < 0) {
			printf("Cannot add digest to compact list\n");
			goto out_free;
		}

		if (getuid() == 0) {
			ret = write_ima_xattr(-1, cur->path, NULL, 0, NULL, 0,
					      algo);
			if (ret < 0) {
				printf("Cannot write xattr to %s\n", cur->path);
				goto out_free;
			}
		}

		if (!strcmp(basename, "upload_digest_lists")) {
			link = strchr(strchr(filename, '-') + 1, '-') + 1;
			unlinkat(dirfd, link, 0);
			ret = symlinkat(filename, dirfd, link);
			if (ret < 0) {
				printf("Cannot create symbolic link\n");
				goto out_free;
			}
		}
	}

	ret = add_path_struct(filename, head_out);
	if (ret < 0)
		goto out_free;

out_free:
	ret = compact_list_flush_all(fd, &list_head);
	if (ret < 0)
		printf("Cannot write digest list to %s\n", filename);
out:
	close(fd);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);

	return ret;
}
