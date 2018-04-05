/*
 * Copyright (C) 2017,2018 Huawei Technologies Duesseldorf GmbH
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
#include <errno.h>

#include "lib.h"

char *digest_lists_dir_path;
int parse_metadata, remove_file, set_ima_algo;

#ifdef CRYPTO
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

int calc_file_digest(u8 *digest, char *path, enum hash_algo algo)
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
	if (data == MAP_FAILED) {
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
#endif

int check_digest(void *data, int len, char *path,
		 enum hash_algo algo, u8 *input_digest)
{
#ifdef CRYPTO
	int digest_len = hash_digest_size[algo];
	u8 digest[digest_len];
	int ret;

	if (parse_metadata)
		return 0;

	if (path)
		ret = calc_file_digest(digest, path, algo);
	else
		ret = calc_digest(digest, data, len, algo);

	if (ret < 0)
		return ret;

	if (memcmp(digest, input_digest, digest_len))
		return -EINVAL;
#endif
	return 0;
}

int read_file_from_path(const char *path, void **buf, loff_t *size)
{
	struct stat st;
	const char *cur_path = path, *basename;
	char tmp_path[256];
	int fd;

	if (digest_lists_dir_path) {
		basename = rindex(path, '/');
		snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
			 digest_lists_dir_path, basename ? basename : path);
		cur_path = tmp_path;
	}

	fd = open(cur_path, O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	stat(cur_path, &st);
	*buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
		    fd, 0);
	if (*buf == MAP_FAILED)
		return -ENOMEM;

	*size = st.st_size;
	return fd;
}

ssize_t write_check(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	while (count > 0) {
		ret = write(fd, buf, count);
		if (ret == -1) {
			pr_err("write() error (%s)\n", strerror(errno));
			return -EIO;
		} else if (!ret) {
			pr_err("write() incomplete, remaining: %ld bytes\n",
			       count);
			return -EIO;
		}

		buf += ret;
		count -= ret;
	}

	return 0;
}

void hexdump(u8 *buf, int len)
{
	while (--len >= 0)
		printf("%02x", *buf++);
}
