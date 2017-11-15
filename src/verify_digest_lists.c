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
 * File: verify_digest_lists.c
 *      Verify digest list metadata and digest lists
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "kernel_ima.h"
#include "lib.h"

int verify_list_metadata(char *path, u8 *digest, int *num_digest_lists,
			 int *num_digests)
{
	int digest_len = hash_digest_size[ima_hash_algo];
	u8 metadata_digest[digest_len];
	void *data, *datap;
	loff_t size, mmap_size, cur_size = 0;
	int digest_lists = 0;
	int ret, fd;

	fd = kernel_read_file_from_path(path, &data, &size, 0,
					READING_DIGEST_LIST_METADATA);
	if (fd < 0) {
		pr_err("Unable to read: %s (%d)\n", path, fd);
		return fd;
	}

	mmap_size = size;

	ret = calc_digest(metadata_digest, data, size, ima_hash_algo);
	if (ret < 0)
		goto out;

	if (memcmp(metadata_digest, digest, digest_len) != 0) {
		pr_err("%s: integrity check failed\n", path);
		ret = -EINVAL;
		goto out;
	}

	datap = data;
	while (size > 0) {
		cur_size = ima_parse_digest_list_metadata(size, datap);
		if (cur_size < 0) {
			ret = -EINVAL;
			goto out;
		}

		size -= cur_size;
		datap += cur_size;
		digest_lists++;
	}

	*num_digest_lists = digest_lists;
	*num_digests = digests;
out:
	munmap(data, mmap_size);
	return ret;
}

void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d: directory containing metadata and digest lists\n"
	       "\t-m <file name>: metadata file name\n"
	       "\t-i <digest>: expected digest of metadata\n"
	       "\t-h: display help\n"
	       "\t-e <algorithm>: digest algorithm\n");
}

int main(int argc, char *argv[])
{
	int c, digest_len, num_digest_lists, num_digests, ret = -EINVAL;
	u8 input_digest[SHA512_DIGEST_SIZE];
	char *digest_ptr = NULL, *cur_dir = "./";
	char *metadata_filename = "metadata";

	while ((c = getopt(argc, argv, "d:m:i:he:")) != -1) {
		switch (c) {
		case 'd':
			cur_dir = optarg;
			break;
		case 'm':
			metadata_filename = optarg;
			break;
		case 'i':
			digest_ptr = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return -EINVAL;
		case 'e':
			if (ima_hash_setup(optarg)) {
				printf("Unknown algorithm %s\n", optarg);
				return -EINVAL;
			}
			break;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	if (digest_ptr == NULL) {
		printf("Expected metadata digest not specified\n");
		return -EINVAL;
	}

	digest_list_path = cur_dir;

	OpenSSL_add_all_digests();

	digest_len = hash_digest_size[ima_hash_algo];
	hex2bin(input_digest, digest_ptr, digest_len);

	ret = verify_list_metadata(metadata_filename, input_digest,
				   &num_digest_lists, &num_digests);
	if (ret == 0)
		printf("num_digest_lists: %d, num_digests: %d\n",
		       num_digest_lists, num_digests);

	EVP_cleanup();
	return ret;
}
