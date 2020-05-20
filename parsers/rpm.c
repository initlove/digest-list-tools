/*
 * Copyright (C) 2017-2020 Huawei Technologies Duesseldorf GmbH
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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <rpm/rpmtag.h>
#include <sys/xattr.h>

#include "parser_lib.h"
#include "selinux.h"
#include "xattr.h"

enum pgp_hash_algo {
	PGP_HASH_MD5			= 1,
	PGP_HASH_SHA1			= 2,
	PGP_HASH_RIPE_MD_160		= 3,
	PGP_HASH_SHA256			= 8,
	PGP_HASH_SHA384			= 9,
	PGP_HASH_SHA512			= 10,
	PGP_HASH_SHA224			= 11,
	PGP_HASH__LAST
};

enum hash_algo pgp_algo_mapping[PGP_HASH__LAST] = {
	[PGP_HASH_MD5] = HASH_ALGO_MD5,
	[PGP_HASH_SHA1] = HASH_ALGO_SHA1,
	[PGP_HASH_SHA224] = HASH_ALGO_SHA224,
	[PGP_HASH_SHA256] = HASH_ALGO_SHA256,
	[PGP_HASH_SHA384] = HASH_ALGO_SHA384,
	[PGP_HASH_SHA512] = HASH_ALGO_SHA512,
};

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

int parser(int fd, struct list_head *head, loff_t buf_size, void *buf,
	   enum parser_ops op)
{
	void *bufp = buf, *bufendp = buf + buf_size;
	struct rpm_hdr *hdr = bufp;
	u32 tags = be32_to_cpu(hdr->tags);
	struct rpm_entryinfo *entry;
	void *datap = bufp + sizeof(*hdr) + tags * sizeof(struct rpm_entryinfo);
	void *sizes = NULL, *modes = NULL, *digests = NULL, *algo_buf = NULL;
	void *dirnames = NULL, *basenames = NULL, *dirindexes = NULL;
	void *filecaps = NULL, *digests_ptr;
	char **dirnames_ptr = NULL, *filecaps_ptr = NULL;
	u32 sizes_count = 0, modes_count = 0, digests_count = 0;
	u32 dirnames_count = 0;
	u16 algo = HASH_ALGO_MD5;
	u8 digest[SHA512_DIGEST_SIZE];
	u8 evm_digest[SHA512_DIGEST_SIZE];
	char path[PATH_MAX];
	int ret = 0, i;

	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};

	if (buf_size < sizeof(*hdr)) {
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
		case RPMTAG_DIRNAMES:
			dirnames = datap + be32_to_cpu(entry->offset);
			dirnames_count = be32_to_cpu(entry->count);
			break;
		case RPMTAG_BASENAMES:
			basenames = datap + be32_to_cpu(entry->offset);
			break;
		case RPMTAG_DIRINDEXES:
			dirindexes = datap + be32_to_cpu(entry->offset);
			break;
		case RPMTAG_FILECAPS:
			filecaps = datap + be32_to_cpu(entry->offset);
			break;
		}

		if (sizes && modes && digests && algo_buf && dirnames &&
		    basenames && dirindexes && filecaps)
			break;
	}

	if (!digests || !sizes || !modes || !dirnames || !basenames ||
	    !dirindexes)
		return 0;

	dirnames_ptr = malloc(sizeof(*dirnames_ptr) * dirnames_count);
	if (!dirnames_ptr)
		return -ENOMEM;

	for (i = 0; i < dirnames_count && dirnames < bufendp; i++) {
		dirnames_ptr[i] = dirnames;
		dirnames += strlen(dirnames) + 1;
	}

	if (i < dirnames_count) {
		ret = -EINVAL;
		goto out;
	}

	if (algo_buf && algo_buf + sizeof(u32) <= bufendp)
		algo = pgp_algo_mapping[be32_to_cpu(*(u32 *)algo_buf)];

	for (i = 0; i < digests_count && digests < bufendp; i++) {
		u16 modifiers = 0;
		int digest_str_len = strlen(digests);
		int basename_str_len = strlen(basenames);
		int filecaps_str_len = filecaps ? strlen(filecaps) : 0;
		char *obj_label;
		u16 mode = 0;
		u32 size = 0;
		u32 dirindex = 0;

		if ((sizes && (i >= sizes_count ||
		    sizes + (i + 1) * sizeof(size) > bufendp)) ||
		    (modes && (i >= modes_count ||
		    modes + (i + 1) * sizeof(mode) > bufendp)) ||
		    (basenames &&
		    basenames + basename_str_len + 1 > bufendp) ||
		    (dirindexes &&
		    dirindexes + (i + 1) * sizeof(dirindex) > bufendp) ||
		    (filecaps + filecaps_str_len + 1 > bufendp) ||
		    (digests + digest_str_len * 2 + 1 > bufendp)) {
			pr_err("RPM header read at invalid offset\n");
			ret = -EINVAL;
			goto out;
		}

		if (!digest_str_len) {
			digests += digest_str_len + 1;
			basenames += basename_str_len + 1;
			if (filecaps)
				filecaps += filecaps_str_len + 1;
			continue;
		}

		size = be32_to_cpu(*(u32 *)(sizes + i * sizeof(size)));
		mode = be16_to_cpu(*(u16 *)(modes + i * sizeof(mode)));
		if (((mode & S_IXUGO) || !(mode & S_IWUGO)) && size)
			modifiers = (1 << COMPACT_MOD_IMMUTABLE);

		digests_ptr = digests;
		digests += digest_str_len + 1;
		dirindex = be32_to_cpu(*(u32 *)
				       (dirindexes + i * sizeof(dirindex)));

		snprintf(path, sizeof(path), "%s%s", dirnames_ptr[dirindex],
			 (char *)basenames);

		basenames += basename_str_len + 1;

		if (filecaps) {
			filecaps_ptr = filecaps;
			filecaps += filecaps_str_len + 1;
		}

		ret = hex2bin(digest, digests_ptr, digest_str_len / 2);
		if (ret < 0)
			goto out;

		ret = 0;

		switch (op) {
		case PARSER_OP_ADD_DIGEST:
			ret = add_digest(fd, head, COMPACT_FILE, modifiers,
					 algo, digest);
			break;
		case PARSER_OP_ADD_DIGEST_TO_HTABLE:
			ret = ima_add_digest_data_entry_kernel(digest, algo,
							       COMPACT_FILE,
							       modifiers);
			if (ret == -EEXIST)
				ret = 0;
			break;
		case PARSER_OP_ADD_META_DIGEST:
		case PARSER_OP_ADD_META_DIGEST_TO_HTABLE:
			ret = get_selinux_label(path, NULL, &obj_label, mode);
			if (ret < 0)
				break;

			ret = calc_metadata_digest(fd, head,
					COMPACT_FILE, modifiers, algo,
					digest, evm_digest, path, 0, 0, mode,
					obj_label, filecaps_str_len ?
				        filecaps_ptr : NULL);

			free(obj_label);

			if (ret < 0)
				break;

			if (op == PARSER_OP_ADD_META_DIGEST_TO_HTABLE) {
				ret = ima_add_digest_data_entry_kernel(
						evm_digest, HASH_ALGO_SHA256,
						COMPACT_METADATA, 0);
				if (ret == -EEXIST)
					ret = 0;

				break;
			}

			ret = add_metadata_digest(fd, head, modifiers,
						  evm_digest);
			break;
		case PARSER_OP_ADD_IMA_XATTR:
			ret = add_ima_xattr(fd, head, COMPACT_FILE, modifiers,
					    algo, digest, path);
			break;
		case PARSER_OP_REMOVE_IMA_XATTR:
			removexattr(path, XATTR_NAME_IMA);
			break;
		case PARSER_OP_ADD_EVM_XATTR:
			write_evm_xattr(path, algo);
			break;
		case PARSER_OP_REMOVE_EVM_XATTR:
			removexattr(path, XATTR_NAME_EVM);
			break;
		case PARSER_OP_REMOVE_INFOFLOW_XATTR:
			removexattr(path, "security.infoflow");
			break;
		case PARSER_OP_DUMP:
			break;
		case PARSER_OP_CHECK_META:
		case PARSER_OP_REPAIR_META:
			check_repair_xattr(path, XATTR_NAME_IMA, digest,
					   digest_str_len / 2, algo, modifiers,
					   (op == PARSER_OP_REPAIR_META));

			check_repair_xattr(path, XATTR_NAME_CAPS, filecaps_ptr,
					   filecaps_str_len, algo, modifiers,
					   (op == PARSER_OP_REPAIR_META));

			check_repair_attr(path, 0, 0, mode,
					  (op == PARSER_OP_REPAIR_META));
			ret = 0;
			break;
		default:
			ret = -ENOTSUP;
			break;
		}

		if (ret < 0)
			return ret;
	}
out:
	free(dirnames_ptr);

	return ret;
}
