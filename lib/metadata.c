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
 * File: metadata.c
 *      Writes digest list metadata.
 */

#include <stdio.h>
#include <fcntl.h>

#include "metadata.h"

static int ima_add_list_metadata(char *metadata_filename, u16 data_algo,
				 u32 digest_len, u8 *digest, u32 signature_len,
				 u8 *signature, u32 file_path_len,
				 char *file_path, u16 data_type)
{
	struct ima_field_data entry_data[DATA__LAST] = {
		[DATA_ALGO] = {.len = sizeof(u16)},
		[DATA_TYPE] = {.len = sizeof(u16)},
	};

	DECLARE_BITMAP(data_mask, DATA__LAST);
	int ret, metadata_len, fd;
	u8 *data;

	bitmap_zero(data_mask, DATA__LAST);
	bitmap_set(data_mask, DATA_ALGO, 1);
	bitmap_set(data_mask, DATA_TYPE, 1);

	entry_data[DATA_ALGO].data = (u8 *)&data_algo;
	entry_data[DATA_DIGEST].len = digest_len;
	entry_data[DATA_DIGEST].data = digest;
	entry_data[DATA_SIGNATURE].len = signature_len;
	entry_data[DATA_SIGNATURE].data = signature;
	entry_data[DATA_FILE_PATH].len = file_path_len;
	entry_data[DATA_FILE_PATH].data = (unsigned char *)file_path;
	entry_data[DATA_REF_ID].len = 0;
	entry_data[DATA_TYPE].data = (u8 *)&data_type;

	metadata_len = ima_get_buflen(DATA__LAST, entry_data, data_mask);
	data = malloc(metadata_len);
	if (data == NULL) {
		printf("Out of memory\n");
		return -ENOMEM;
	}

	ret = ima_write_buf(data, data + metadata_len, NULL,
			    DATA__LAST, entry_data, NULL, data_mask,
			    ENFORCE_FIELDS | ENFORCE_BUFEND, "entry data");
	if (ret < 0)
		goto out;

	fd = open(metadata_filename, O_WRONLY | O_APPEND);
	if (fd < 0)
		goto out;

	metadata_len = cpu_to_le32(metadata_len);
	write(fd, &metadata_len, sizeof(u32));
	write(fd, data, metadata_len);
	close(fd);
out:
	free(data);
	return ret;
}

int write_digests_and_metadata(Header hdr, char *outdir,
			       char *metadata_filename,
			       enum input_formats input_fmt,
			       char *input_filename,
			       enum digest_data_types output_fmt,
			       int is_mutable)
{
	int ret;
	char digest_list_filename[MAX_FILENAME_LENGTH];
	int digest_len = hash_digest_size[ima_hash_algo];
	u16 data_algo = cpu_to_le16(ima_hash_algo);
	u16 data_type = cpu_to_le16(output_fmt);
	u8 digest[digest_len];
	unsigned int signature_len = 0;
	u8 *signature;

	if (input_fmt == INPUT_FMT_DIGEST_LIST_ASCII)
		ret = compact_list_from_digest_list_ascii(input_filename,
							  outdir,
							  digest_list_filename,
							  is_mutable);
	else if (output_fmt == DATA_TYPE_COMPACT_LIST)
		ret = compact_list_from_rpm(hdr, outdir, digest_list_filename);
	else if (output_fmt == DATA_TYPE_RPM)
		ret = write_rpm_header(hdr, outdir, digest_list_filename);

	if (ret < 0) {
		if (ret == -ENOENT)
			return 0;

		printf("Failed to write digest list, ret: %d\n", ret);
		return ret;
	}

	ret = calc_file_digest(digest_list_filename, digest, ima_hash_algo);
	if (ret < 0) {
		printf("Failed to calculate metadata digest, ret: %d\n", ret);
		return ret;
	}

	if (output_fmt == DATA_TYPE_RPM)
		get_rpm_header_signature(hdr, &signature, &signature_len);

	ret = ima_add_list_metadata(metadata_filename, data_algo,
				    digest_len, digest, signature_len,
				    signature, strlen(digest_list_filename) + 1,
				    digest_list_filename, data_type);
	if (ret < 0)
		printf("Failed to write metadata, ret: %d\n", ret);

	return ret;
}
