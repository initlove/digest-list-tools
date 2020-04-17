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
 * File: compact_tlv.c
 *      Parses TLV compact list.
 */

#include <errno.h>
#include <sys/xattr.h>
#include <linux/magic.h>

#include "parser_lib.h"
#include "xattr.h"

#define items_data(id) (items[id] ? items[id]->data : NULL)
#define items_data_len(id) (items[id] ? items[id]->len : 0)

int parser(int fd, struct list_head *head, loff_t size, void *buf,
	   enum parser_ops op, char *backup_dir)
{
	u32 len;
	u16 modifiers;
	u32 i_meta[4] = { 0 };
	u64 fs_magic = 0;
	struct _tlv_item *item_ptr;
	struct _tlv_item *items[ID__LAST] = { NULL };
	enum hash_algo evm_algo = HASH_ALGO_SHA256;
	u8 evm_digest[SHA512_DIGEST_SIZE], *evm_digest_ptr;
	void *bufp = buf, *bufendp = buf + size;
	struct compact_list_hdr hdr, *hdrp;
	u8 evm_xattr_value = EVM_XATTR_HMAC;
	int ret, i, j, count;

	while (bufp < bufendp) {
		if (bufp + sizeof(hdr) > bufendp) {
			pr_err("compact list, invalid data\n");
			return -EINVAL;
		}

		hdrp = bufp;
		memcpy(&hdr, hdrp, sizeof(hdr));

		if (hdr.version != 2) {
			pr_err("compact list, unsupported version\n");
			return -EINVAL;
		}

		if (ima_canonical_fmt) {
			hdr.type = le16_to_cpu(hdr.type);
			hdr.modifiers = le16_to_cpu(hdr.modifiers);
			hdr.algo = le16_to_cpu(hdr.algo);
			hdr.count = le32_to_cpu(hdr.count);
			hdr.datalen = le32_to_cpu(hdr.datalen);
		}

		if (hdr.algo >= HASH_ALGO__LAST)
			return -EINVAL;

		if (hdr.type >= COMPACT__LAST) {
			pr_err("TLV compact list, invalid type %d\n",
			       hdr.type);
			return -EINVAL;
		}

		bufp += sizeof(hdr);

		for (i = 0; i < hdr.count; i++) {
			if (bufp + sizeof(u8) > bufendp) {
				pr_err("TLV compact list, invalid data\n");
				return -EINVAL;
			}

			for (j = 0; j < ID__LAST; j++)
				items[j] = NULL;

			count = *(u8 *)bufp++;

			for (j = 0; j < count; j++) {
				if (bufp + sizeof(**items) > bufendp) {
					pr_err("TLV compact list, "
					       "invalid data\n");
					return -EINVAL;
				}

				item_ptr = (struct _tlv_item *)bufp;
				if (item_ptr->id >= ID__LAST) {
					pr_err("TLV compact list, "
					       "invalid data\n");
					return -EINVAL;
				}

				bufp += sizeof(*item_ptr);

				len = item_ptr->len;
				if (ima_canonical_fmt)
					len = le32_to_cpu(len);

				items[item_ptr->id] = item_ptr;

				if (bufp + len > bufendp) {
					pr_err("TLV compact list, "
					       "invalid data\n");
					return -EINVAL;
				}

				bufp += len;
			}

			modifiers = hdr.modifiers;

			for (j = 0; j < 4; j++) {
				if (!items_data(ID_INODE_UID + j))
					continue;

				i_meta[j] =
					*(u32 *)items_data(ID_INODE_UID + j);
				if (ima_canonical_fmt)
					i_meta[j] = le32_to_cpu(i_meta[j]);
			}

			if (((i_meta[2] & S_IXUGO) || !(i_meta[2] & S_IWUGO)) &&
			    i_meta[3])
				modifiers |= (1 << COMPACT_MOD_IMMUTABLE);

			if (items_data(ID_FSMAGIC)) {
				fs_magic = *(u64 *)items_data(ID_FSMAGIC);
				if (ima_canonical_fmt)
					fs_magic = le64_to_cpu(fs_magic);
			}

			ret = 0;

			switch (op) {
			case PARSER_OP_ADD_DIGEST:
				ret = add_digest(fd, head, hdr.type,
						 modifiers, hdr.algo,
						 items_data(ID_DIGEST));
				break;
			case PARSER_OP_ADD_DIGEST_TO_HTABLE:
				ret = ima_add_digest_data_entry_kernel(
							items_data(ID_DIGEST),
							hdr.algo, hdr.type,
							modifiers);
				if (ret == -EEXIST)
					ret = 0;
				break;
			case PARSER_OP_UPDATE_DIGEST:
				ret = update_digest(hdr.algo,
						    items_data(ID_DIGEST),
						    (char *)items_data(ID_PATH),
						    backup_dir);
				if (ret < 0)
					break;
			case PARSER_OP_ADD_META_DIGEST:
			case PARSER_OP_ADD_META_DIGEST_TO_HTABLE:
				if (!items_data(ID_EVM_DIGEST) ||
				    op == PARSER_OP_UPDATE_DIGEST) {
					ret = calc_metadata_digest(fd, head,
					   hdr.type, modifiers,
					   hdr.algo, items_data(ID_DIGEST),
					   evm_digest,
					   (char *)items_data(ID_PATH),
					   i_meta[0], i_meta[1], i_meta[2],
					   (char *)items_data(ID_OBJ_LABEL),
					   (char *)items_data(ID_CAPS));
					if (ret < 0)
						break;

					evm_digest_ptr = evm_digest;
				} else {
					evm_digest_ptr =
						items_data(ID_EVM_DIGEST);
				}

				if (op == PARSER_OP_UPDATE_DIGEST &&
				    items_data(ID_EVM_DIGEST)) {
					memcpy(items[ID_EVM_DIGEST]->data,
					       evm_digest,
					       hash_digest_size[evm_algo]);
					break;
				}

				if (op == PARSER_OP_ADD_META_DIGEST_TO_HTABLE) {
					ret = ima_add_digest_data_entry_kernel(
							evm_digest_ptr,
							HASH_ALGO_SHA256,
							COMPACT_METADATA, 0);
					if (ret == -EEXIST)
						ret = 0;

					break;
				}

				ret = add_metadata_digest(fd, head, modifiers,
							  evm_digest_ptr);
				break;
			case PARSER_OP_RESTORE_FILES:
				ret = restore_files((char *)items_data(ID_PATH),
						    backup_dir);
				break;
			case PARSER_OP_ADD_IMA_XATTR:
				if (fs_magic == TMPFS_MAGIC)
					break;

				ret = add_ima_xattr(fd, head, hdr.type,
						modifiers, hdr.algo,
						items_data(ID_DIGEST),
						(char *)items_data(ID_PATH));
				break;
			case PARSER_OP_REMOVE_IMA_XATTR:
				if (fs_magic == TMPFS_MAGIC)
					break;

				removexattr((char *)items_data(ID_PATH),
					    XATTR_NAME_IMA);
				break;
			case PARSER_OP_ADD_EVM_XATTR:
				lsetxattr((char *)items_data(ID_PATH),
					  XATTR_NAME_EVM, &evm_xattr_value, 1,
					  0);
				break;
			case PARSER_OP_REMOVE_EVM_XATTR:
				if (fs_magic == TMPFS_MAGIC)
					break;

				removexattr((char *)items_data(ID_PATH),
					    XATTR_NAME_EVM);
				break;
			case PARSER_OP_REMOVE_INFOFLOW_XATTR:
				if (fs_magic == TMPFS_MAGIC)
					break;

				removexattr((char *)items_data(ID_PATH),
					    "security.infoflow");
				break;
			case PARSER_OP_DUMP:
				compact_list_tlv_dump_items(items);
				break;
			case PARSER_OP_CHECK_META:
			case PARSER_OP_REPAIR_META:
				check_repair_xattr((char *)items_data(ID_PATH),
						XATTR_NAME_SELINUX,
						items_data(ID_OBJ_LABEL),
						items_data_len(ID_OBJ_LABEL),
						hdr.algo, modifiers,
						(op == PARSER_OP_REPAIR_META));

				check_repair_xattr((char *)items_data(ID_PATH),
						XATTR_NAME_IMA,
						items_data(ID_DIGEST),
						items_data_len(ID_DIGEST),
						hdr.algo, modifiers,
						(op == PARSER_OP_REPAIR_META));

				check_repair_xattr((char *)items_data(ID_PATH),
						XATTR_NAME_CAPS,
						items_data(ID_CAPS),
						items_data_len(ID_CAPS),
						hdr.algo, modifiers,
						(op == PARSER_OP_REPAIR_META));

				check_repair_attr((char *)items_data(ID_PATH),
						i_meta[0], i_meta[1], i_meta[2],
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

		if (i != hdr.count ||
		    bufp != (void *)hdrp + sizeof(hdr) + hdr.datalen) {
			pr_err("compact list, invalid data\n");
			return -EINVAL;
		}
	}

	return 0;
}
