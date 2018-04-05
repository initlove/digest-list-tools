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

int compact_list_from_rpm(Header rpm, char *outdir, char *output_path)
{
	u16 digest_algo;
	u32 rpm_digest_algo, default_rpmdigestalgo = PGP_HASH_MD5;
	rpmtd rpm_digestalgo_td = rpmtdNew();
	rpm_count_t data_count;
	rpmfi fi;
	u8 *output;
	int ret, fd, datalen = 0, i, digest_len;
	struct compact_list_hdr hdr = {0, 0, 0, 0};

	get_rpm_path(rpm, outdir, output_path, DATA_SUB_TYPE_COMPACT_LIST);

	if (strstr(output_path, "gpg-pubkey") != NULL)
		return -ENOENT;

	ret = headerGet(rpm, RPMTAG_FILEDIGESTALGO, rpm_digestalgo_td, 0);
	if (ret < 0) {
		rpm_digest_algo = default_rpmdigestalgo;
		return -EINVAL;
	}

	rpm_digest_algo = rpmtdGetNumber(rpm_digestalgo_td);
	digest_algo = pgp_algo_mapping[rpm_digest_algo];
	digest_len = hash_digest_size[digest_algo];
	rpmtdReset(rpm_digestalgo_td);

	fi = rpmfiNew(NULL, rpm, RPMTAG_FILEDIGESTS, RPMFI_KEEPHEADER);
	if (fi == NULL)
		return -EINVAL;

	data_count = rpmfiFC(fi);
	output = malloc(digest_len * data_count);
	if (output == NULL)
		return -ENOMEM;

	for (i = 0; i < data_count; i++) {
		if (rpmfiNext(fi) == -1)
			break;

		if (strlen(rpmfiFN(fi)) == 0)
			continue;

		hex2bin(output + datalen, rpmfiFN(fi), digest_len);
		hdr.count++;
		datalen += digest_len;
	}

	fi = rpmfiFree(fi);

	hdr.entry_id = COMPACT_DIGEST;
	hdr.algo = digest_algo;
	hdr.datalen = datalen;

	if (ima_canonical_fmt) {
		hdr.entry_id = cpu_to_le16(hdr.entry_id);
		hdr.algo = cpu_to_le16(hdr.algo);
		hdr.count = cpu_to_le32(hdr.count);
		hdr.datalen = cpu_to_le32(hdr.datalen);
	}

	fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		goto out;

	ret = write_check(fd, &hdr, sizeof(hdr));
	if (ret < 0)
		goto out_close;

	ret = write_check(fd, output, hdr.datalen);
out_close:
	close(fd);
out:
	free(output);
	return ret;
}

static int compact_list_from_digest_list_ascii(char *input_path, char *outdir,
					       char *output_path,
					       int is_mutable)
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

	if (stat(input_path, &st) != 0)
		return -EACCES;

	if (st.st_size == 0)
		return -EINVAL;

	inputfd = open(input_path, O_RDONLY);
	if (inputfd < 0)
		return -EACCES;

	data = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE, inputfd, 0);
	if (data == MAP_FAILED) {
		ret = -ENOMEM;
		goto out;
	}

	datap = data;

	input_basename = rindex(input_path, '/');
	if (input_basename == NULL)
		input_basename = input_path;
	else
		input_basename += 1;

	snprintf(output_path, MAX_PATH_LENGTH, "%s/compact-%s",
		 outdir, input_basename);

	outputfd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (outputfd < 0) {
		printf("Unable to write %s\n", output_path);
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
			printf("Digest algorithm mismatch, skipping: %s\n",
			       line);
			continue;
		}

		hex2bin(digest, line + algo_prefix_len, digest_len);
		ret = write_check(outputfd, digest, digest_len);
		if (ret < 0)
			goto out_outputfd;

		hdr.count++;
		datalen += digest_len;
	}

	hdr.entry_id = is_mutable ? COMPACT_DIGEST_MUTABLE : COMPACT_DIGEST;
	hdr.algo = ima_hash_algo;
	hdr.datalen = datalen;

	if (ima_canonical_fmt) {
		hdr.entry_id = cpu_to_le16(hdr.entry_id);
		hdr.algo = cpu_to_le16(ima_hash_algo);
		hdr.count = cpu_to_le32(hdr.count);
		hdr.datalen = cpu_to_le32(datalen);
	}

	ret = lseek(outputfd, 0, SEEK_SET);
	if (ret < 0) {
		pr_err("lseek() error, ret: %d\n", ret);
		goto out_outputfd;
	}

	ret = write_check(outputfd, &hdr, sizeof(hdr));
out_outputfd:
	close(outputfd);
out:
	close(inputfd);
	if (data)
		munmap(data, st.st_size);

	return ret;
}

int digest_list_from_ascii(char *outdir, char *metadata_path,
			   char *input_path,
			   enum digest_data_sub_types output_fmt,
			   int is_mutable, int sign, char *gpg_key_name)
{
	char digest_list_path[MAX_PATH_LENGTH];
	int ret;

	ret = compact_list_from_digest_list_ascii(input_path, outdir,
						  digest_list_path,
						  is_mutable);
	if (ret < 0)
		return ret;

	if (sign) {
		ret = sign_digest_list(digest_list_path, gpg_key_name);
		if (ret < 0)
			return ret;
	}

	return write_digests_and_metadata(outdir, metadata_path,
					  digest_list_path, output_fmt,
					  sign);
}
