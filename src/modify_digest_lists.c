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
 * File: verify_digest_lists.c
 *      Verify digest list metadata and digest lists
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "securityfs.h"
#include "lib.h"

#define CURRENT_DIR "/etc/ima/digest_lists"

static int modify_list_metadata(char *filename, int fd_new, int id_to_remove)
{
	void *data, *datap;
	loff_t size, mmap_size, cur_size = 0;
	int ret = 0, fd;
	int num_entry = 0;

	fd = read_file_from_path(filename, &data, &size);
	if (fd < 0) {
		pr_err("Unable to read: %s (%d)\n", filename, fd);
		return fd;
	}

	mmap_size = size;

	datap = data;
	while (size > 0) {
		if (id_to_remove != -1 && num_entry++ == id_to_remove)
			remove_file = 1;

		cur_size = ima_parse_digest_list_metadata(size, datap);
		if (cur_size < 0) {
			ret = -EINVAL;
			goto out;
		}

		if (fd_new != -1 && !remove_file) {
			ret = write_check(fd_new, datap, cur_size);
			if (ret < 0) {
				pr_err("Failed to write new metadata\n");
				return -EACCES;
			}
		} else if (remove_file) {
			pr_info("Entry #%d deleted\n",
				id_to_remove);
			remove_file = 0;
		}

		size -= cur_size;
		datap += cur_size;
	}
out:
	munmap(data, mmap_size);
	close(fd);
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
	       "\t-r <id num>: ID of entry to remove\n"
	       "\t-s: set ima_algo extended attribute\n"
	);
}

int main(int argc, char *argv[])
{
	int c, ret = -EINVAL;
	char path_old[MAX_PATH_LENGTH], path_new[MAX_PATH_LENGTH];
	char *cur_dir = CURRENT_DIR;
	char *metadata_filename = "metadata";
	long id = -1, fd = -1;

	while ((c = getopt(argc, argv, "d:m:he:r:s")) != -1) {
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
			break;
		case 'e':
			if (ima_hash_setup(optarg)) {
				printf("Unknown algorithm %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'r':
			id = strtoul(optarg, NULL, 10);
			break;
		case 's':
			set_ima_algo = 1;
			break;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	parse_metadata = 1;
	digest_lists_dir_path = cur_dir;

	snprintf(path_old, sizeof(path_old), "%s/%s", cur_dir,
		 metadata_filename);
	snprintf(path_new, sizeof(path_new), "%s.new", path_old);

	if (id != -1) {
		fd = open(path_new, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd < 0) {
			pr_err("Unable to write to %s\n", path_new);
			return -EACCES;
		}
	}

	ret = modify_list_metadata(metadata_filename, fd, id);
	if (id == -1)
		return ret;

	if (ret == 0) {
		ret = rename(path_new, path_old);
		if (ret < 0)
			pr_err("Unable to rename %s to %s\n",
			       path_new, path_old);
	} else {
		unlink(path_new);
	}

	return ret;
}
