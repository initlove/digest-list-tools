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
 * File: kernel_ima.c
 *      Includes IMA functions.
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "kernel_ima.h"

int digests;

int ima_add_digest_data_entry(u8 *digest, u8 is_mutable)
{
	digests++;
	return 0;
}

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

#define RPMTAG_FILEDIGESTS 1035
#define RPMTAG_FILEMODES 1030

struct rpm_hdr {
	u32 magic;
	u32 reserved;
	u32 tags;
	u32 datasize;
} __attribute__((packed));

struct rpm_entryinfo {
	int32_t tag;
	u32 type;
	int32_t offset;
	u32 count;
} __attribute__((packed));


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

static int ima_parse_compact_list(loff_t size, void *buf)
{
	void *bufp = buf, *bufendp = buf + size;
	int digest_len = hash_digest_size[ima_hash_algo];
	struct compact_list_hdr *hdr;
	u8 is_mutable = 0;
	int ret, i;

	while (bufp < bufendp) {
		if (bufp + sizeof(*hdr) > bufendp) {
			pr_err("compact list, missing header\n");
			return -EINVAL;
		}

		hdr = bufp;

		hdr->entry_id = le16_to_cpu(hdr->entry_id);
		hdr->count = le32_to_cpu(hdr->count);
		hdr->datalen = le32_to_cpu(hdr->datalen);

		switch (hdr->entry_id) {
		case COMPACT_DIGEST_MUTABLE:
			is_mutable = 1;
		case COMPACT_DIGEST:
			break;
		default:
			pr_err("compact list, invalid data type\n");
			return -EINVAL;
		}

		bufp += sizeof(*hdr);

		for (i = 0; i < hdr->count &&
		     bufp + digest_len <= bufendp; i++) {
			ret = ima_add_digest_data_entry(bufp, is_mutable);
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

	return 0;
}

static int ima_parse_rpm(loff_t size, void *buf)
{
	void *bufp = buf, *bufendp = buf + size;
	struct rpm_hdr *hdr = bufp;
	u32 tags = be32_to_cpu(hdr->tags);
	struct rpm_entryinfo *entry;
	void *datap = bufp + sizeof(*hdr) + tags * sizeof(struct rpm_entryinfo);
	void *digests = NULL, *modes = NULL;
	u32 digests_count, modes_count;
	int digest_len = hash_digest_size[ima_hash_algo];
	u8 digest[digest_len];
	int ret, i;

	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};

	if (size < sizeof(*hdr)) {
		pr_err("Missing RPM header\n");
		return -EINVAL;
	}

	if (memcmp(bufp, rpm_header_magic, sizeof(rpm_header_magic))) {
		pr_err("Invalid RPM header\n");
		return -EINVAL;
	}

	bufp += sizeof(*hdr);

	for (i = 0; i < tags && (bufp + sizeof(*entry)) <= bufendp;
	     i++, bufp += sizeof(*entry)) {
		entry = bufp;

		if (be32_to_cpu(entry->tag) == RPMTAG_FILEDIGESTS) {
			digests = datap + be32_to_cpu(entry->offset);
			digests_count = be32_to_cpu(entry->count);
		}
		if (be32_to_cpu(entry->tag) == RPMTAG_FILEMODES) {
			modes = datap + be32_to_cpu(entry->offset);
			modes_count = be32_to_cpu(entry->count);
		}
		if (digests && modes)
			break;
	}

	if (digests == NULL)
		return 0;

	for (i = 0; i < digests_count && digests < bufendp; i++) {
		u8 is_mutable = 0;
		u16 mode;

		if (strlen(digests) == 0) {
			digests++;
			continue;
		}

		if (modes) {
			if (i < modes_count &&
			    modes + (i + 1) * sizeof(mode) > bufendp) {
				pr_err("RPM header read at invalid offset\n");
				return -EINVAL;
			}

			mode = be16_to_cpu(*(u16 *)(modes + i * sizeof(mode)));
			if (!(mode & (S_IXUGO | S_ISUID | S_ISVTX)) &&
			    (mode & S_IWUGO))
				is_mutable = 1;
		}

		if (digests + digest_len * 2 + 1 > bufendp) {
			pr_err("RPM header read at invalid offset\n");
			return -EINVAL;
		}

		ret = hex2bin(digest, digests, digest_len);
		if (ret < 0)
			return -EINVAL;

		ret = ima_add_digest_data_entry(digest, is_mutable);
		if (ret < 0 && ret != -EEXIST)
			return ret;

		digests += digest_len * 2 + 1;
	}

	return 0;
}

static int ima_parse_digest_list_data(struct ima_field_data *data)
{
	int digest_len = hash_digest_size[ima_hash_algo];
	u8 digest[digest_len];
	void *digest_list;
	loff_t digest_list_size;
	u16 data_algo = le16_to_cpu(*(u16 *)data[DATA_ALGO].data);
	u16 data_type = le16_to_cpu(*(u16 *)data[DATA_TYPE].data);
	int ret, fd;

	if (data_algo != ima_hash_algo) {
		pr_err("Incompatible digest algorithm, expected %s\n",
		       hash_algo_name[ima_hash_algo]);
		return -EINVAL;
	}

	fd = kernel_read_file_from_path((char *)data[DATA_FILE_PATH].data,
					&digest_list, &digest_list_size,
					0, READING_DIGEST_LIST);
	if (fd < 0) {
		pr_err("Unable to open file: %s (%d)\n",
		       data[DATA_FILE_PATH].data, fd);
		return fd;
	}

	calc_digest(digest, digest_list, digest_list_size, ima_hash_algo);
	if (memcmp(digest, data[DATA_DIGEST].data, data[DATA_DIGEST].len)) {
		pr_err("Digest verification for %s failed\n",
		       data[DATA_FILE_PATH].data);
		ret = -EINVAL;
		goto out;
	}

	ret = ima_add_digest_data_entry(digest, 0);
	if (ret < 0) {
		if (ret == -EEXIST)
			ret = 1;

		goto out;
	}

	switch (data_type) {
	case DATA_TYPE_COMPACT_LIST:
		ret = ima_parse_compact_list(digest_list_size, digest_list);
		break;
	case DATA_TYPE_RPM:
		ret = ima_parse_rpm(digest_list_size, digest_list);
		break;
	default:
		pr_err("Parser for data type %d not implemented\n", data_type);
		ret = -EINVAL;
	}

	if (ret < 0)
		pr_err("Error parsing file: %s (%d)\n",
		       data[DATA_FILE_PATH].data, ret);
out:
	munmap(digest_list, digest_list_size);
	close(fd);
	return ret;
}

ssize_t ima_parse_digest_list_metadata(loff_t size, void *buf)
{
	struct ima_field_data entry;

	struct ima_field_data entry_data[DATA__LAST] = {
		[DATA_ALGO] = {.len = sizeof(u16)},
		[DATA_TYPE] = {.len = sizeof(u16)},
	};

	DECLARE_BITMAP(data_mask, DATA__LAST);
	void *bufp = buf, *bufendp = buf + size;
	int ret;

	bitmap_zero(data_mask, DATA__LAST);
	bitmap_set(data_mask, DATA_ALGO, 1);
	bitmap_set(data_mask, DATA_TYPE, 1);

	ret = ima_parse_buf(bufp, bufendp, &bufp, 1, &entry, NULL, NULL,
			    ENFORCE_FIELDS, "digest list entry");
	if (ret < 0)
		goto out;

	ret = ima_parse_buf(entry.data, entry.data + entry.len, NULL,
			    DATA__LAST, entry_data, NULL, data_mask,
			    ENFORCE_FIELDS | ENFORCE_BUFEND,
			    "digest list entry data");
	if (ret < 0)
		goto out;

	ret = ima_parse_digest_list_data(entry_data);
out:
	return ret < 0 ? ret : bufp - buf;
}
