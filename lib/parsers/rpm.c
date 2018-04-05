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
 * File: rpm.c
 *      Parses RPM package headers.
 */

#include "kernel_ima.h"
#include "pgp.h"

#define RPMTAG_FILESIZES 1028
#define RPMTAG_FILEMODES 1030
#define RPMTAG_FILEDIGESTS 1035
#define RPMTAG_FILEDIGESTALGO 5011

/**************
 * RPM parser *
 **************/
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

int ima_parse_rpm(loff_t size, void *buf, void *ctx, u16 data_algo,
		  callback_func func)
{
	void *bufp = buf, *bufendp = buf + size;
	struct rpm_hdr *hdr = bufp;
	u32 tags = be32_to_cpu(hdr->tags);
	struct rpm_entryinfo *entry;
	void *datap = bufp + sizeof(*hdr) + tags * sizeof(struct rpm_entryinfo);
	void *sizes = NULL, *modes = NULL, *digests = NULL, *algo_buf = NULL;
	u32 sizes_count = 0, modes_count = 0, digests_count = 0;
	u16 digest_algo = HASH_ALGO_MD5;
	u8 digest[IMA_MAX_DIGEST_SIZE];
	int ret = 0, i, digest_len;

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

		switch (be32_to_cpu(entry->tag)) {
		case RPMTAG_FILESIZES:
			sizes = datap + be32_to_cpu(entry->offset);
			sizes_count = be32_to_cpu(entry->count);
			break;
		case RPMTAG_FILEMODES:
			modes = datap + be32_to_cpu(entry->offset);
			modes_count = be32_to_cpu(entry->count);
			break;
		case RPMTAG_FILEDIGESTS:
			digests = datap + be32_to_cpu(entry->offset);
			digests_count = be32_to_cpu(entry->count);
			break;
		case RPMTAG_FILEDIGESTALGO:
			algo_buf = datap + be32_to_cpu(entry->offset);
			break;
		}

		if (sizes && modes && digests && algo_buf)
			break;
	}

	if (digests == NULL)
		return 0;

	if (algo_buf && algo_buf + sizeof(u32) <= bufendp)
		digest_algo = pgp_algo_mapping[be32_to_cpu(*(u32 *)algo_buf)];

	digest_len = hash_digest_size[digest_algo];

	for (i = 0; i < digests_count && digests < bufendp; i++) {
		u8 flags = DIGEST_FLAG_IMMUTABLE;
		u16 mode;
		u32 size;

		if (strlen(digests) == 0) {
			digests++;
			continue;
		}

		if ((sizes && (i >= sizes_count ||
		    sizes + (i + 1) * sizeof(size) > bufendp)) ||
		    (modes && (i >= modes_count ||
		    modes + (i + 1) * sizeof(mode) > bufendp)) ||
		    (digests + digest_len * 2 + 1 > bufendp)) {
			pr_err("RPM header read at invalid offset\n");
			return -EINVAL;
		}

		if (sizes) {
			size = be32_to_cpu(*(u32 *)(sizes + i * sizeof(size)));
			if (!size)
				flags = 0;
		}

		if (flags && modes) {
			mode = be16_to_cpu(*(u16 *)(modes + i * sizeof(mode)));
			if (!(mode & (S_IXUGO | S_ISUID | S_ISVTX)) &&
			    (mode & S_IWUGO))
				flags = 0;
		}

		ret = hex2bin(digest, digests, digest_len);
		if (ret < 0)
			return -EINVAL;

		ret = ima_add_digest_data_entry(digest, digest_algo, flags,
						DATA_TYPE_REG_FILE, ACTION_ADD);
		if (ret < 0 && ret != -EEXIST)
			return ret;

		digests += digest_len * 2 + 1;
	}

	return ret < 0 ? ret : bufp - buf;
}
