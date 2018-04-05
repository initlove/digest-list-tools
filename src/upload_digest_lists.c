/*
 * Copyright (C) 2018 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: upload_digest_lists.c
 *      Upload digest list metadata and digest lists
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <keyutils.h>
#include <asm/unistd.h>

#include "securityfs.h"
#include "lib.h"

#define CURRENT_DIR "/etc/ima/digest_lists"

static int upload_list_metadata(char *path)
{
	void *data, *datap;
	loff_t size, mmap_size, cur_size = 0;
	int ret, fd;

	/* this allows the parser to open metadata without appraisal */
	ret = ima_init_upload(DIGEST_LIST_METADATA);
	if (ret < 0) {
		printf("Unable to upload metadata, ret: %d\n", ret);
		return ret;
	}

	fd = read_file_from_path(path, &data, &size);
	if (fd < 0) {
		pr_err("Unable to read: %s (%d)\n", path, fd);
		return fd;
	}

	mmap_size = size;

	ret = ima_upload_metadata(data, size);
	if (ret < 0) {
		printf("Unable to upload metadata, ret: %d\n", ret);
		goto out;
	}

	ima_end_upload();

	/* after this, only digest lists can be accessed or upload is denied */
	ret = ima_init_upload(DIGEST_LIST_DATA);
	if (ret < 0) {
		printf("Unable to upload digests, ret: %d\n", ret);
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
	}

	ima_end_upload();
out:
	munmap(data, mmap_size);
	close(fd);

	if (getpid() == 1)
		ret = execl("/sbin/init", "init", NULL);

	return ret;
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d: directory containing metadata and digest lists\n"
	       "\t-m <file name>: metadata file name\n"
	       "\t-h: display help\n"
	       "\t-e <algorithm>: digest algorithm\n"
	       "\t-c: create IMA keyring\n");
}

int main(int argc, char *argv[])
{
	int c, ret = -EINVAL;
	char *cur_dir = CURRENT_DIR;
	char *metadata_filename = "metadata";
	key_serial_t ima_id;

	while ((c = getopt(argc, argv, "d:m:he:c")) != -1) {
		switch (c) {
		case 'd':
			cur_dir = optarg;
			break;
		case 'm':
			metadata_filename = optarg;
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
		case 'c':
			ima_id = syscall(__NR_add_key, "keyring", "_ima",
					 NULL, 0, KEY_SPEC_USER_KEYRING);
			if (ima_id == -1)
				return -EPERM;
			break;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	digest_lists_dir_path = cur_dir;

	ret = upload_list_metadata(metadata_filename);
	if (ret == 0)
		printf("digest_lists: %d, digests: %d\n",
		       digest_lists, digests);

	if (sent_digests != digests) {
		printf("Number of digests mismatch, expected: %d, sent: %d\n",
		       digests, sent_digests);
		ret = -EINVAL;
	}

	return ret;
}
