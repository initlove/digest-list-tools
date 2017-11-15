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
 * File: lib.c
 *      Includes libraries.
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "lib.h"

char *digest_list_path;

int calc_digest(u8 *digest, void *data, int len, enum hash_algo algo)
{
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	const EVP_MD *md = EVP_get_digestbyname(hash_algo_name[algo]);

	if (mdctx == NULL)
		return -EINVAL;

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
		return -EINVAL;

	if (EVP_DigestUpdate(mdctx, data, len) != 1)
		return -EINVAL;

	if (EVP_DigestFinal_ex(mdctx, digest, NULL) != 1)
		return -EINVAL;

	EVP_MD_CTX_destroy(mdctx);
	return 0;
}

int calc_file_digest(char *path, u8 *digest, enum hash_algo algo)
{
	void *data;
	struct stat st;
	int fd, ret = 0;

	if (stat(path, &st) != 0)
		return -EACCES;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -EACCES;

	data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ret = calc_digest(digest, data, st.st_size, algo);
out:
	if (data)
		munmap(data, st.st_size);

	close(fd);
	return ret;
}

int kernel_read_file_from_path(const char *path, void **buf, loff_t *size,
			       loff_t max_size, enum kernel_read_file_id id)
{
	struct stat st;
	const char *cur_path = path, *basename;
	char tmp_path[256];
	int fd;

	if (digest_list_path) {
		basename = rindex(path, '/');
		snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
			 digest_list_path, basename ? basename : path);
		cur_path = tmp_path;
	}

	fd = open(cur_path, O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	stat(cur_path, &st);
	*buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
		    fd, 0);
	if (*buf == NULL)
		return -ENOMEM;

	*size = st.st_size;
	return fd;
}
