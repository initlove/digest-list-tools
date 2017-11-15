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
 * File: compact_list.c
 *      Writes compact digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "compact_list.h"

int compact_list_from_rpm(Header rpm, char *outdir, char *output_filename)
{
	int digest_len = hash_digest_size[ima_hash_algo];
	int ret, fd, datalen = 0, i;

	rpm_tagtype_t data_type;
	rpm_count_t data_count;
	char **data;

	u8 *output;

	struct compact_list_hdr hdr = {0, 0, 0};

	get_rpm_filename(rpm, outdir, output_filename, DATA_TYPE_COMPACT_LIST);

	ret = check_rpm_digest_algo(rpm, output_filename);
	if (ret < 0)
		return ret;

	ret = headerGetEntry(rpm, RPMTAG_FILEDIGESTS, &data_type,
			     (void **)&data, &data_count);
	if (ret < 0)
		return -EINVAL;

	output = malloc(digest_len * data_count);
	if (output == NULL)
		return -ENOMEM;

	for (i = 0; i < data_count; i++) {
		if (strlen(data[i]) == 0)
			continue;

		hex2bin(output + datalen, data[i], digest_len);
		hdr.count++;
		datalen += digest_len;
	}

	hdr.entry_id = COMPACT_DIGEST;
	hdr.entry_id = cpu_to_le16(hdr.entry_id);
	hdr.count = cpu_to_le32(hdr.count);
	hdr.datalen = cpu_to_le32(datalen);

	fd = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -EACCES;

	write(fd, &hdr, sizeof(hdr));
	write(fd, output, datalen);

	close(fd);
	free(output);
	return 0;
}

int compact_list_from_digest_list_ascii(char *input_filename, char *outdir,
					char *output_filename, int is_mutable)
{
	const char *algo_name = hash_algo_name[ima_hash_algo];
	int algo_prefix_len = strlen(algo_name) + 1;
	int digest_len = hash_digest_size[ima_hash_algo];
	u8 digest[digest_len];
	char *data, *datap, *line, *input_basename;
	int datalen = 0;
	struct stat st;
	int ret = 0, inputfd = -1, outputfd;

	struct compact_list_hdr hdr = {0, 0, 0};

	if (stat(input_filename, &st) != 0)
		return -EACCES;

	if (st.st_size == 0)
		return -EINVAL;

	inputfd = open(input_filename, O_RDONLY);
	if (inputfd < 0)
		return -EACCES;

	data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE, inputfd, 0);
	if (data == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	datap = data;

	input_basename = rindex(input_filename, '/');
	if (input_basename == NULL)
		input_basename = input_filename;
	else
		input_basename += 1;

	snprintf(output_filename, MAX_FILENAME_LENGTH, "%s/compact-%s",
		 outdir, input_basename);

	outputfd = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (outputfd < 0) {
		printf("Unable to write %s\n", output_filename);
		ret = -EACCES;
		goto out;
	}

	lseek(outputfd, sizeof(hdr), SEEK_SET);

	while (true) {
		line = strsep(&datap, "\n");
		if (line == NULL)
			break;

		if (strlen(line) < algo_prefix_len + digest_len * 2)
			continue;

		if (strncmp(line, algo_name, algo_prefix_len - 1)) {
			printf("Digest algorithm mismatch, expected: %s\n",
			       algo_name);
			return -EINVAL;
		}

		hex2bin(digest, line + algo_prefix_len, digest_len);
		write(outputfd, digest, digest_len);
		hdr.count++;
		datalen += digest_len;
	}

	hdr.entry_id = is_mutable ? COMPACT_DIGEST_MUTABLE : COMPACT_DIGEST;
	hdr.entry_id = cpu_to_le16(hdr.entry_id);
	hdr.count = cpu_to_le32(hdr.count);
	hdr.datalen = cpu_to_le32(datalen);

	lseek(outputfd, 0, SEEK_SET);
	write(outputfd, &hdr, sizeof(hdr));
	close(outputfd);
out:
	close(inputfd);
	if (data)
		munmap(data, st.st_size);

	return ret;
}
