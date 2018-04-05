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
 * File: metadata.c
 *      Writes digest list metadata.
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/xattr.h>

#include "metadata.h"

static int ima_add_list_metadata(char *metadata_path,
				 u16 data_algo, u16 data_type,
				 u32 data_type_ext_len, u8 *data_type_ext,
				 u16 digest_algo, u32 digest_len, u8 *digest,
				 u16 sig_fmt, u32 signature_len, u8 *signature,
				 u32 file_path_len, char *file_path,
				 u32 data_length)
{
	struct ima_field_data entry_data[DATA__LAST] = {
		[DATA_ALGO] = {.len = sizeof(u16)},
		[DATA_TYPE] = {.len = sizeof(u16)},
		[DATA_DIGEST_ALGO] = {.len = sizeof(u16)},
		[DATA_SIG_FMT] = {.len = sizeof(u16)},
		[DATA_LENGTH] = {.len = sizeof(u32)},
	};

	DECLARE_BITMAP(data_mask, DATA__LAST);
	int ret, metadata_len, fd;
	u8 *data;

	bitmap_zero(data_mask, DATA__LAST);
	bitmap_set(data_mask, DATA_ALGO, 1);
	bitmap_set(data_mask, DATA_TYPE, 1);
	bitmap_set(data_mask, DATA_DIGEST_ALGO, 1);
	bitmap_set(data_mask, DATA_SIG_FMT, 1);
	bitmap_set(data_mask, DATA_LENGTH, 1);

	if (ima_canonical_fmt) {
		data_algo = cpu_to_le16(data_algo);
		data_type = cpu_to_le16(data_type);
		digest_algo = cpu_to_le16(digest_algo);
		sig_fmt = cpu_to_le16(sig_fmt);
		data_length = cpu_to_le32(data_length);
	}

	entry_data[DATA_ALGO].data = (u8 *)&data_algo;
	entry_data[DATA_TYPE].data = (u8 *)&data_type;
	entry_data[DATA_TYPE_EXT].len = data_type_ext_len;
	entry_data[DATA_TYPE_EXT].data = data_type_ext;
	entry_data[DATA_DIGEST_ALGO].data = (u8 *)&digest_algo;
	entry_data[DATA_DIGEST].len = digest_len;
	entry_data[DATA_DIGEST].data = digest;
	entry_data[DATA_SIG_FMT].data = (u8 *)&sig_fmt;
	entry_data[DATA_SIG].len = signature_len;
	entry_data[DATA_SIG].data = signature;
	entry_data[DATA_FILE_PATH].len = file_path_len;
	entry_data[DATA_FILE_PATH].data = (unsigned char *)file_path;
	entry_data[DATA_LENGTH].data = (u8 *)&data_length;

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

	fd = open(metadata_path, O_WRONLY | O_APPEND);
	if (fd < 0)
		goto out;

	if (ima_canonical_fmt)
		metadata_len = cpu_to_le32(metadata_len);

	ret = write_check(fd, &metadata_len, sizeof(u32));
	if (ret < 0)
		goto out_close;

	ret = write_check(fd, data, metadata_len);
out_close:
	close(fd);
out:
	free(data);
	return ret;
}

int write_digests_and_metadata(char *outdir, char *metadata_path,
			       char *digest_list_path,
			       enum digest_data_sub_types output_fmt, int sign)
{
	char key_path[MAX_PATH_LENGTH];
	char digest_list_sig_path[MAX_PATH_LENGTH];
	u16 data_algo = (output_fmt == DATA_SUB_TYPE_DEB_PACKAGE) ?
			HASH_ALGO_MD5 : ima_hash_algo;
	u16 digest_algo = ima_hash_algo;
	u16 data_sig_fmt = SIG_FMT_NONE;
	u8 digest[IMA_MAX_DIGEST_SIZE];
	loff_t signature_len = 0;
	u8 *signature = NULL;
	int ret, fd = -1, fd_sig = -1;
	u8 *buf;
	struct stat st;
	size_t buf_len;
	u32 data_sub_type = output_fmt;

	if (ima_canonical_fmt)
		data_sub_type = cpu_to_le32(output_fmt);

	if (stat(digest_list_path, &st) == -1) {
		pr_err("Unable to access %s\n", digest_list_path);
		return -EACCES;
	}

	snprintf(digest_list_sig_path, sizeof(digest_list_sig_path),
		 "%s.sig", digest_list_path);

	fd_sig = read_file_from_path(digest_list_sig_path,
				     (void **)&signature, &signature_len);
	if (fd_sig >= 0) {
		data_sig_fmt = SIG_FMT_PGP;
		pgp_get_digest_algo(signature, signature_len, &digest_algo);

		fd = open(digest_list_path, O_WRONLY | O_APPEND);
		if (fd < 0) {
			printf("Unable to update digest list %s, ret: %d\n",
			       digest_list_path, fd);
			ret = fd;
			goto out;
		}

		ret = pgp_get_signature_data(signature, signature_len, &buf,
					     &buf_len);
		if (!ret) {
			ret = write_check(fd, buf, buf_len);
			free(buf);

			if (ret < 0) {
				close(fd);
				goto out;
			}
		}

		close(fd);

		if (sign) {
			ret = get_default_key(outdir, key_path,
					      digest_list_sig_path);
			if (ret < 0 && ret != -EEXIST) {
				pr_err("Unable to find the PGP key for %s\n",
					digest_list_sig_path);
				return ret;
			}

			if (!ret) {
				ret = write_pgp_key(metadata_path, key_path);
				if (ret < 0) {
					pr_err("Cannot write PGP key to %s\n",
					       key_path);
					return ret;
				}
			}
		}
	}

	ret = calc_file_digest(digest, digest_list_path, digest_algo);
	if (ret < 0) {
		printf("Failed to calculate metadata digest, ret: %d\n", ret);
		return ret;
	}

	ret = ima_add_list_metadata(metadata_path, data_algo,
				    DATA_TYPE_DIGEST_LIST,
				    sizeof(data_sub_type), (u8 *)&data_sub_type,
				    digest_algo, hash_digest_size[digest_algo],
				    digest, data_sig_fmt,
				    signature_len, signature,
				    strlen(digest_list_path) + 1,
				    digest_list_path, st.st_size);
	if (ret < 0)
		printf("Failed to write metadata, ret: %d\n", ret);
out:
	if (fd_sig >= 0)
		close(fd_sig);

	if (signature)
		munmap(signature, signature_len);

	return ret;
}

int write_parser_data(char *parser_data_path, char *binary_path)
{
	u16 parser_version = REQ_PARSER_VERSION;
	u16 parser_digest_algo = ima_hash_algo;
	int digest_len = hash_digest_size[parser_digest_algo];
	u8 parser_digest[digest_len];
	int ret, fd;

	ret = calc_file_digest(parser_digest, binary_path,
			       parser_digest_algo);
	if (ret < 0) {
		printf("Failed to calculate parser digest, ret: %d\n", ret);
		return ret;
	}

	fd = open(parser_data_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return fd;

	if (ima_canonical_fmt) {
		parser_version = cpu_to_le16(parser_version);
		parser_digest_algo = cpu_to_le16(parser_digest_algo);
	}

	ret = write_check(fd, &parser_version, sizeof(parser_version));
	if (ret < 0)
		goto out;

	ret = write_check(fd, &parser_digest_algo, sizeof(parser_digest_algo));
	if (ret < 0)
		goto out;

	ret = write_check(fd, parser_digest, digest_len);
	if (ret < 0)
		goto out;

	ret = write_check(fd, PARSER_STRING, sizeof(PARSER_STRING) - 1);
out:
	close(fd);
	return ret;
}

int write_parser_metadata(char *parser_data_path, char *parser_metadata_path,
			  char *binary_path)
{
	u16 data_type = DATA_TYPE_PARSER;
	u16 data_sig_fmt = SIG_FMT_NONE;
	u16 parser_digest_algo = ima_hash_algo;
	u16 sig_digest_algo = ima_hash_algo;
	u8 *parser_data, *parser_digest;
	loff_t parser_data_len;
	u8 *parser_sig_data = NULL;
	char sig_path[MAX_PATH_LENGTH];
	loff_t parser_sig_len = 0;
	int ret, fd, fd_sig = -1;

	fd = read_file_from_path(parser_data_path, (void **)&parser_data,
				 &parser_data_len);
	if (fd < 0) {
		pr_err("Unable to obtain parser data, ret: %d\n", fd);
		return fd;
	}

	ret = ima_check_parser(parser_data, parser_data_len,
			       &parser_digest, &parser_digest_algo);
	if (ret < 0) {
		pr_err("Invalid parser data\n");
		goto out;
	}

	if (parser_digest_algo != ima_hash_algo) {
		removexattr(binary_path, "security.ima");
		setxattr(binary_path, "security.ima_algo",
			 &parser_digest_algo, sizeof(parser_digest_algo), 0);
	}

	snprintf(sig_path, sizeof(sig_path), "%s.sig", parser_data_path);
	fd_sig = read_file_from_path(sig_path, (void **)&parser_sig_data,
				     &parser_sig_len);
	if (fd_sig < 0) {
		parser_sig_data = NULL;
		parser_sig_len = 0;
	} else {
		ret = pgp_get_digest_algo(parser_sig_data, parser_sig_len,
					  &sig_digest_algo);
		if (!ret)
			data_sig_fmt = SIG_FMT_PGP;
	}

	ret = ima_add_list_metadata(parser_metadata_path, parser_digest_algo,
				    data_type, parser_data_len, parser_data,
				    sig_digest_algo, 0, NULL, data_sig_fmt,
				    parser_sig_len, parser_sig_data,
				    strlen(binary_path) + 1,
				    binary_path, 0);
	if (ret < 0)
		printf("Failed to write metadata, ret: %d\n", ret);
out:
	if (parser_data) {
		munmap(parser_data, parser_data_len);
		close(fd);
	}

	if (parser_sig_data) {
		munmap(parser_sig_data, parser_sig_len);
		close(fd_sig);
	}
	return ret;
}

int write_metadata_header(char *metadata_path)
{
	u16 version = REQ_METADATA_VERSION;

	if (ima_canonical_fmt)
		version = cpu_to_le16(version);

	return ima_add_list_metadata(metadata_path, ima_hash_algo,
				     DATA_TYPE_HEADER, sizeof(u16),
				     (u8 *)&version, ima_hash_algo, 0,
				     NULL, SIG_FMT_NONE, 0, NULL, 0, NULL, 0);
}

int write_pgp_key(char *metadata_path, char *pgp_key_path)
{
	u8 *key;
	loff_t key_len;
	int ret, fd;

	fd = read_file_from_path(pgp_key_path, (void **)&key, &key_len);
	if (fd < 0)
		return fd;

	ret = ima_add_list_metadata(metadata_path, ima_hash_algo, DATA_TYPE_KEY,
				    key_len, key, ima_hash_algo, 0, NULL,
				    SIG_FMT_NONE, 0, NULL,
				    strlen(pgp_key_path) + 1, pgp_key_path,
				    key_len);
	munmap(key, key_len);
	close (fd);
	return ret;
}
