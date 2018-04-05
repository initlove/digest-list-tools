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
 * File: kernel_ima.c
 *      Includes IMA functions.
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "kernel_ima.h"
#include "rpm.h"
#include "deb.h"

int current, parser_task, ima_policy_flag;
int ima_digest_list_actions = IMA_MEASURE | IMA_APPRAISE;
int num_entry;

#ifdef __BIG_ENDIAN__
int ima_canonical_fmt = 1;
#else
int ima_canonical_fmt = 0;
#endif

int ima_get_buflen(int maxfields, struct ima_field_data *fields,
		   unsigned long *len_mask)
{
	int len = 0, i;

	for (i = 0; i < maxfields; i++) {
		if (len_mask == NULL || !test_bit(i, len_mask))
			len += sizeof(u32);

		len += fields[i].len;
	}

	return len;
}

int ima_hash_algo = HASH_ALGO_SHA256;

int ima_hash_setup(char *str)
{
	int i;

	for (i = 0; i < HASH_ALGO__LAST; i++) {
		if (strcmp(str, hash_algo_name[i]) == 0) {
			ima_hash_algo = i;
			break;
		}
	}

	if (i == HASH_ALGO__LAST)
		return -EINVAL;

	return 0;
}

int ima_parse_buf(void *bufstartp, void *bufendp, void **bufcurp,
		  int maxfields, struct ima_field_data *fields, int *curfields,
		  unsigned long *len_mask, int enforce_mask, char *bufname)
{
	void *bufp = bufstartp;
	int i;

	for (i = 0; i < maxfields; i++) {
		if (len_mask == NULL || !test_bit(i, len_mask)) {
			if (bufp > (bufendp - sizeof(u32)))
				break;

			fields[i].len = le32_to_cpu(*(u32 *)bufp);

			bufp += sizeof(u32);
		}

		if (bufp > (bufendp - fields[i].len))
			break;

		fields[i].data = bufp;
		bufp += fields[i].len;
	}

	if ((enforce_mask & ENFORCE_FIELDS) && i != maxfields) {
		pr_err("%s: nr of fields mismatch: expected: %d, current: %d\n",
		       bufname, maxfields, i);
		return -EINVAL;
	}

	if ((enforce_mask & ENFORCE_BUFEND) && bufp != bufendp) {
		pr_err("%s: buf end mismatch: expected: %p, current: %p\n",
		       bufname, bufendp, bufp);
		return -EINVAL;
	}

	if (curfields)
		*curfields = i;

	if (bufcurp)
		*bufcurp = bufp;

	return 0;
}

int ima_write_buf(void *bufstartp, void *bufendp, void **bufcurp,
		  int maxfields, struct ima_field_data *fields, int *curfields,
		  unsigned long *len_mask, int enforce_mask, char *bufname)
{
	void *bufp = bufstartp;
	int i;

	for (i = 0; i < maxfields; i++) {
		if (len_mask == NULL || !test_bit(i, len_mask)) {
			u32 field_len = fields[i].len;

			if (bufp > (bufendp - sizeof(u32)))
				break;

			field_len = cpu_to_le32(field_len);

			memcpy(bufp, &field_len, sizeof(field_len));

			bufp += sizeof(u32);
		}

		if (bufp > (bufendp - fields[i].len))
			break;

		memcpy(bufp, fields[i].data, fields[i].len);
		bufp += fields[i].len;
	}

	if ((enforce_mask & ENFORCE_FIELDS) && i != maxfields) {
		pr_err("%s: nr of fields mismatch: expected: %d, current: %d\n",
		       bufname, maxfields, i);
		return -EINVAL;
	}

	if ((enforce_mask & ENFORCE_BUFEND) && bufp != bufendp) {
		pr_err("%s: buf end mismatch: expected: %p, current: %p\n",
		       bufname, bufendp, bufp);
		return -EINVAL;
	}

	if (curfields)
		*curfields = i;

	if (bufcurp)
		*bufcurp = bufp;

	return 0;
}

/***********************
 * Compact list parser *
 ***********************/
static int ima_parse_compact_list(loff_t size, void *buf, u16 data_algo,
				  void *ctx, callback_func func)
{
	void *bufp = buf, *bufendp = buf + size;
	struct compact_list_hdr *hdr;
	u8 flags = 0;
	u16 type = DATA_TYPE_REG_FILE;
	int ret, i, digest_len;

	if (current != parser_task)
		return -EPERM;

	while (bufp < bufendp) {
		if (bufp + sizeof(*hdr) > bufendp) {
			pr_err("compact list, missing header\n");
			return -EINVAL;
		}

		hdr = bufp;

		if (ima_canonical_fmt) {
			hdr->entry_id = le16_to_cpu(hdr->entry_id);
			hdr->algo = le16_to_cpu(hdr->algo);
			hdr->count = le32_to_cpu(hdr->count);
			hdr->datalen = le32_to_cpu(hdr->datalen);
		}

		if (hdr->algo < 0 || hdr->algo >= HASH_ALGO__LAST)
			return -EINVAL;

		if (hdr->algo != ima_hash_algo)
			flags |= DIGEST_FLAG_DIGEST_ALGO;

		digest_len = hash_digest_size[hdr->algo];

		switch (hdr->entry_id) {
		case COMPACT_DIGEST:
		case COMPACT_DIGEST_LIST:
			flags |= DIGEST_FLAG_IMMUTABLE;

			if (hdr->entry_id == COMPACT_DIGEST_LIST)
				type = DATA_TYPE_DIGEST_LIST;
			break;
		case COMPACT_DIGEST_MUTABLE:
			break;
		default:
			pr_err("compact list, invalid data type\n");
			return -EINVAL;
		}

		bufp += sizeof(*hdr);

		for (i = 0; i < hdr->count &&
		     bufp + digest_len <= bufendp; i++) {
			ret = ima_add_digest_data_entry(bufp, hdr->algo,
							flags, type,
							ACTION_ADD);
			if (ret < 0 && ret != -EEXIST)
				return ret;

			bufp += digest_len;
		}

		if (i != hdr->count ||
		    bufp != (void *)hdr + sizeof(*hdr) + hdr->datalen) {
			pr_err("compact list, invalid data\n");
			return -EINVAL;
		}
	}

	return bufp - buf;
}

/************
 * Callback *
 ************/
struct callback_ctx {
	u16 data_algo;
	enum digest_data_sub_types sub_type;
};

int upload_callback(void *ctx, char *line)
{
	char *digest_str;
	u8 digest[IMA_MAX_DIGEST_SIZE];
	struct callback_ctx *c = (struct callback_ctx *)ctx;
	const char *packages_gz_str = "Packages.gz";
	const char *algo_name = hash_algo_name[c->data_algo];
	int l_gz = strlen(packages_gz_str);
	u8 flags = 0;
	enum digest_data_types type = DATA_TYPE_REG_FILE;

	switch (c->sub_type) {
	case DATA_SUB_TYPE_DEB_PACKAGE:
		digest_str = line;
		break;
	case DATA_SUB_TYPE_DEB_PACKAGES_GZ:
		if (strncasecmp(line, algo_name, strlen(algo_name)))
			return 0;

		digest_str = strchr(line, ':') + 2;
		flags = DIGEST_FLAG_IMMUTABLE;
		type = DATA_TYPE_DIGEST_LIST;
		break;
	case DATA_SUB_TYPE_DEB_RELEASE:
		if (strncmp(line + strlen(line) - l_gz, packages_gz_str, l_gz))
			return 0;

		digest_str = line + 1;
		flags = DIGEST_FLAG_IMMUTABLE;
		type = DATA_TYPE_DIGEST_LIST;
		break;
	default:
		return 0;
	}

	hex2bin(digest, digest_str, hash_digest_size[c->data_algo]);

	return ima_add_digest_data_entry(digest, c->data_algo, flags, type,
					 ACTION_ADD);
}

int (*parser_func[DATA_SUB_TYPE__LAST])(loff_t size, void *buf, u16 data_algo,
					void *ctx, callback_func func) = {
	[DATA_SUB_TYPE_COMPACT_LIST] = ima_parse_compact_list,
	[DATA_SUB_TYPE_RPM] = ima_parse_rpm,
	[DATA_SUB_TYPE_DEB_PACKAGE] = ima_parse_deb_package,
	[DATA_SUB_TYPE_DEB_PACKAGES_GZ] = ima_parse_deb_packages_gz,
	[DATA_SUB_TYPE_DEB_RELEASE] = ima_parse_deb_release,
};

/***************************
 * Digest list data parser *
 ***************************/
static int ima_parse_digest_list_data(u16 data_algo, u16 digest_algo,
				      u16 sub_type, u8 *digest, char *path,
				      u32 data_length)
{
	struct callback_ctx ctx = {data_algo, sub_type};
	void *digest_list;
	loff_t digest_list_size;
	int ret, fd;

	if (parse_metadata)
		return 0;

	fd = read_file_from_path(path, &digest_list, &digest_list_size);
	if (fd < 0) {
		pr_err("Unable to open file: %s (%d)\n", path, fd);
		return fd;
	}

	ret = check_digest(digest_list, digest_list_size, NULL,
			   digest_algo, digest);
	if (ret < 0) {
		pr_err("Digest verification for %s failed\n", path);
		goto out;
	}

	if (parser_func[sub_type] == NULL) {
		pr_err("Parser for type %d not implemented\n", sub_type);
		ret = -EINVAL;
		goto out;
	}

	ret = parser_func[sub_type](data_length, digest_list, data_algo,
				    (void *)&ctx, upload_callback);
	if (ret < 0) {
		pr_err("Error parsing file: %s (%d)\n", path, ret);
		goto out;
	}

	ret = ima_flush_digest_list_buffer();
out:
	munmap(digest_list, digest_list_size);
	close(fd);
	return ret;
}

/*******************************
 * Digest list metadata viewer *
 *******************************/
#define SPACES 2
#define DIGEST_LEN 4
#define ID_LENGTH 6

static char *digest_metadata_fields_str[DATA__LAST] = {
	[DATA_ALGO] = "DATA_ALGO",
	[DATA_TYPE] = "TYPE",
	[DATA_TYPE_EXT] = "TYPE_EXT",
	[DATA_DIGEST_ALGO] = "DIGEST_ALGO",
	[DATA_DIGEST] = "DIGEST",
	[DATA_SIG_FMT] = "SIG_FMT",
	[DATA_SIG] = "SIG",
	[DATA_FILE_PATH] = "FILE_PATH",
	[DATA_LENGTH] = "DATA_LENGTH",
};

static int digest_metadata_fields_str_len[DATA__LAST] = {
	[DATA_ALGO] = 9,
	[DATA_TYPE] = 11,
	[DATA_TYPE_EXT] = 12,
	[DATA_DIGEST_ALGO] = 11,
	[DATA_DIGEST] = DIGEST_LEN * 2,
	[DATA_SIG_FMT] = 7,
	[DATA_SIG] = DIGEST_LEN * 2,
	[DATA_FILE_PATH] = 30,
	[DATA_LENGTH] = 11,
};

static char *digest_data_types_str[DATA_TYPE_REG_FILE + 1] = {
	[DATA_TYPE_HEADER] = "header",
	[DATA_TYPE_DIGEST_LIST] = "digest_list",
	[DATA_TYPE_PARSER] = "parser",
	[DATA_TYPE_REG_FILE] = "file",
	[DATA_TYPE_KEY] = "key",
};

static char *digest_data_sub_types_str[DATA_SUB_TYPE__LAST] = {
	[DATA_SUB_TYPE_COMPACT_LIST] = "compact",
	[DATA_SUB_TYPE_RPM] = "rpm",
	[DATA_SUB_TYPE_DEB_RELEASE] = "deb_release",
	[DATA_SUB_TYPE_DEB_PACKAGES_GZ] = "deb_packages",
	[DATA_SUB_TYPE_DEB_PACKAGE] = "deb_package",
};

static char *data_sig_formats_str[SIG_FMT_PKCS7 + 1] = {
	[SIG_FMT_NONE] = "",
	[SIG_FMT_IMA] = "ima",
	[SIG_FMT_PGP] = "pgp",
	[SIG_FMT_PKCS7] = "pkcs7",
};

static void print_metadata_header(void)
{
	int i;

	pr_info("%*s", ID_LENGTH, "ID");

	for (i = 0; i < ARRAY_SIZE(digest_metadata_fields_str); i++) {
		printf("%*s", SPACES, "");
		pr_info("%*s", digest_metadata_fields_str_len[i],
			digest_metadata_fields_str[i]);
	}

	pr_info("\n");
}

static void print_metadata(struct ima_field_data *entry_data)
{
	enum digest_data_types data_type;
	enum digest_data_sub_types sub_type;
	enum data_sig_formats sig_fmt;
	char *file_ptr;
	int i, len;

	pr_info("%*d", ID_LENGTH, num_entry++);

	for (i = 0; i < ARRAY_SIZE(digest_metadata_fields_str); i++) {
		printf("%*s", SPACES, "");

		if (!entry_data[i].len) {
			pr_info("%*s", digest_metadata_fields_str_len[i], "");
			continue;
		}

		switch(i) {
		case DATA_ALGO:
		case DATA_DIGEST_ALGO:
			pr_info("%*s", digest_metadata_fields_str_len[i],
				hash_algo_name[*(u16 *)entry_data[i].data]);
			break;
		case DATA_TYPE:
			data_type = *(u16 *)entry_data[i].data;
			pr_info("%*s", digest_metadata_fields_str_len[i],
				digest_data_types_str[data_type]);
			break;
		case DATA_TYPE_EXT:
			data_type = *(u16 *)entry_data[DATA_TYPE].data;
			if (data_type == DATA_TYPE_DIGEST_LIST) {
				sub_type = *(u32 *)entry_data[i].data;
				pr_info("%*s",
					digest_metadata_fields_str_len[i],
					digest_data_sub_types_str[sub_type]);
			} else {
				len = min(DIGEST_LEN, entry_data[i].len);
				pr_info("%*s",
					digest_metadata_fields_str_len[i] -
					len * 2, "");
				hexdump(entry_data[i].data, len);
			}
			break;
		case DATA_DIGEST:
			hexdump(entry_data[i].data, DIGEST_LEN);
			break;
		case DATA_SIG_FMT:
			sig_fmt = *(u16 *)entry_data[i].data;
			pr_info("%*s", digest_metadata_fields_str_len[i],
				data_sig_formats_str[sig_fmt]);
			break;
		case DATA_SIG:
			hexdump(entry_data[i].data, DIGEST_LEN);
			break;
		case DATA_FILE_PATH:
			file_ptr = strrchr((char *)entry_data[i].data, '/');
			if (!file_ptr)
				file_ptr = (char *)entry_data[i].data;
			else
				file_ptr++;

			file_ptr = strndup(file_ptr,
					min(entry_data[i].len,
					    digest_metadata_fields_str_len[i]));
			pr_info("%*s", digest_metadata_fields_str_len[i],
				file_ptr);
			free(file_ptr);
			break;
		case DATA_LENGTH:
			pr_info("%*d", digest_metadata_fields_str_len[i],
				*(u16 *)entry_data[i].data);
			break;
		}
	}

	printf("\n");
}

/*******************************
 * Digest list metadata parser *
 *******************************/
int ima_check_parser(u8 *data, u32 data_len,
		     u8 **digest, u16 *digest_algo)
{
	int parser_len = sizeof(PARSER_STRING) - 1;
	int digest_len, expected_data_len;
	u8 *datap = data + data_len - parser_len;
	u16 version, algo;

	version = *(u16 *)data;
	if (ima_canonical_fmt)
		version = le16_to_cpu(version);

	if (version > REQ_PARSER_VERSION)
		return -EINVAL;

	algo = *(u16 *)(data + sizeof(u16));
	if (ima_canonical_fmt)
		algo = le16_to_cpu(algo);

	if (algo < 0 || algo >= HASH_ALGO__LAST)
		return -EINVAL;

	digest_len = hash_digest_size[algo];
	expected_data_len = sizeof(u16) * 2 + digest_len + parser_len;
	if (data_len != expected_data_len)
		return -EINVAL;

	if (memcmp(datap, PARSER_STRING, parser_len))
		return -EINVAL;
	*digest = data + 2 * sizeof(u16);
	*digest_algo = algo;
	return 0;
}

static int ima_check_signature(u16 data_algo, u8 *type_ext, u32 type_ext_len,
			       u8 *digest, u32 digest_len, u16 sig_fmt,
			       u8 *sig, u32 sig_len)
{
	return 0;
}

static int ima_digest_list_create_key(u8 *payload, u32 len)
{
	return 0;
}

static void ima_digest_list_set_algo(char *pathname, u16 algo)
{
	if (ima_fd == -1 && !set_ima_algo)
		return;

	removexattr(pathname, XATTR_NAME_IMA);
	setxattr(pathname, XATTR_NAME_IMA_ALGO, &algo, sizeof(algo), 0);
}

static void ima_remove_file(char *path)
{
	char path_tmp[MAX_PATH_LENGTH];
	struct stat st;

	if (!remove_file || !path)
		return;

	unlink(path);
	snprintf(path_tmp, sizeof(path_tmp), "%s.sig", path);
	if (!stat(path_tmp, &st))
		unlink(path_tmp);
}

ssize_t ima_parse_digest_list_metadata(loff_t size, void *buf)
{
	struct ima_field_data entry;

	struct ima_field_data entry_data[DATA__LAST] = {
		[DATA_ALGO] = {.len = sizeof(u16)},
		[DATA_TYPE] = {.len = sizeof(u16)},
		[DATA_DIGEST_ALGO] = {.len = sizeof(u16)},
		[DATA_SIG_FMT] = {.len = sizeof(u16)},
		[DATA_LENGTH] = {.len = sizeof(u32)},
	};

	DECLARE_BITMAP(data_mask, DATA__LAST);
	void *bufp = buf, *bufendp = buf + size;
	u16 data_algo, data_type, digest_algo, sig_fmt, version, parser_algo;
	u8 flags = DIGEST_FLAG_IMMUTABLE;
	u8 *digest;
	char *path;
	int ret;

	if (current != parser_task)
		return -EPERM;

	bitmap_zero(data_mask, DATA__LAST);
	bitmap_set(data_mask, DATA_ALGO, 1);
	bitmap_set(data_mask, DATA_TYPE, 1);
	bitmap_set(data_mask, DATA_DIGEST_ALGO, 1);
	bitmap_set(data_mask, DATA_SIG_FMT, 1);
	bitmap_set(data_mask, DATA_LENGTH, 1);

	ret = ima_parse_buf(bufp, bufendp, &bufp, 1, &entry, NULL, NULL,
			    ENFORCE_FIELDS, "metadata list entry");
	if (ret < 0)
		return ret;

	ret = ima_parse_buf(entry.data, entry.data + entry.len, NULL,
			    DATA__LAST, entry_data, NULL, data_mask,
			    ENFORCE_FIELDS | ENFORCE_BUFEND,
			    "metadata entry data");
	if (ret < 0)
		return ret;

	data_algo = *(u16 *)entry_data[DATA_ALGO].data;
	data_type = *(u16 *)entry_data[DATA_TYPE].data;
	digest_algo = *(u16 *)entry_data[DATA_DIGEST_ALGO].data;
	sig_fmt = *(u16 *)entry_data[DATA_SIG_FMT].data;
	digest = entry_data[DATA_DIGEST].data;
	path = (char *)entry_data[DATA_FILE_PATH].data;

	if (ima_canonical_fmt) {
		data_algo = le16_to_cpu(data_algo);
		data_type = le16_to_cpu(data_type);
		digest_algo = le16_to_cpu(digest_algo);
		sig_fmt = le16_to_cpu(sig_fmt);
	}

	switch (data_type) {
	case DATA_TYPE_HEADER:
		if (entry_data[DATA_TYPE_EXT].len != sizeof(u16))
			return -EINVAL;

		version = le16_to_cpu(*(u16 *)entry_data[DATA_TYPE_EXT].data);
		if (version > REQ_METADATA_VERSION)
			return -EINVAL;

		goto out;
	case DATA_TYPE_DIGEST_LIST:
		/* digest lists, except the compact, are parsed in user space */
		break;
	case DATA_TYPE_KEY:
		ret = ima_digest_list_create_key(entry_data[DATA_ALGO].data,
						 entry_data[DATA_ALGO].len);
		goto out;
	case DATA_TYPE_PARSER:
		ret = ima_check_parser(entry_data[DATA_TYPE_EXT].data,
				       entry_data[DATA_TYPE_EXT].len,
				       &digest, &parser_algo);
		if (ret < 0)
			return ret;

		if (parser_algo != data_algo) {
			pr_err("Parser digest algorithm mismatch\n");
			return -EINVAL;
		}

		digest_algo = parser_algo;
		break;
	default:
		pr_err("Invalid data type %d\n", data_type);
		return -EINVAL;
	}

	if (digest_algo != ima_hash_algo) {
		if (digest_algo < 0 || digest_algo >= HASH_ALGO__LAST) {
			pr_err("Unknown algorithm\n");
			return -EINVAL;
		}

		flags |= DIGEST_FLAG_DIGEST_ALGO;
		ima_digest_list_set_algo(path, digest_algo);
	}

	if (ima_policy_flag & IMA_APPRAISE) {
		ret = ima_check_signature(data_algo,
					  entry_data[DATA_TYPE_EXT].data,
					  entry_data[DATA_TYPE_EXT].len,
					  digest, entry_data[DATA_DIGEST].len,
					  sig_fmt, entry_data[DATA_SIG].data,
					  entry_data[DATA_SIG].len);
		if (ret < 0) {
			if (ret == -ENOENT)
				goto out;

			pr_err("Failed signature verification of: %s (%d)\n",
			       path, ret);
			return ret;
		}
	} else {
		ima_digest_list_actions &= ~IMA_APPRAISE;
	}

	ret = ima_add_digest_data_entry(digest, digest_algo, flags, data_type,
					ACTION_RESET);
	if (ret < 0 && ret != -EEXIST)
		return ret;

	if (data_type == DATA_TYPE_DIGEST_LIST) {
		u32 data_sub_type, data_length;

		if (entry_data[DATA_TYPE_EXT].len != sizeof(u32))
			return -EINVAL;

		data_sub_type = *(u32 *)entry_data[DATA_TYPE_EXT].data;
		data_length = *(u32 *)entry_data[DATA_LENGTH].data;

		if (ima_canonical_fmt) {
			data_sub_type = le32_to_cpu(data_sub_type);
			data_length = le32_to_cpu(data_length);
		}

		ret = ima_parse_digest_list_data(data_algo, digest_algo,
						 data_sub_type, digest, path,
						 data_length);
		if (ret < 0)
			return ret;
	}
out:
	if (ima_fd == -1) {
		if (data_type == DATA_TYPE_HEADER) {
			num_entry = 0;
			print_metadata_header();
		}

		print_metadata(entry_data);
	}

	if (remove_file)
		ima_remove_file(path);

	return bufp - buf;
}
