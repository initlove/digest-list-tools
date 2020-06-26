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
 * File: compact_list.c
 *      Writes compact digest lists.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <keyutils.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/vfs.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <sys/capability.h>
#include <selinux/selinux.h>

#include "compact_list.h"
#include "crypto.h"
#include "xattr.h"
#include "evm.h"
#include "lib.h"
#include "cap.h"
#include "ima_list.h"
#include "selinux.h"

#define DIGEST_LIST_LABEL "system_u:object_r:etc_t:s0"
#define DIGEST_LIST_MODE 0644
#define DIGEST_LIST_ALGO HASH_ALGO_SHA256

char *compact_types_str[COMPACT__LAST] = {
	[COMPACT_KEY] = "key",
	[COMPACT_PARSER] = "parser",
	[COMPACT_FILE] = "file",
	[COMPACT_METADATA] = "metadata",
};

char *compact_modifiers_str[COMPACT_MOD__LAST] = {
	[COMPACT_MOD_IMMUTABLE] = "immutable",
};

static char *compact_list_tlv_ids[ID__LAST] = {
	[ID_DIGEST] = "IMA digest",
	[ID_EVM_DIGEST] = "EVM digest",
	[ID_PATH] = "path",
	[ID_INODE_UID] = "inode UID",
	[ID_INODE_GID] = "inode GID",
	[ID_INODE_MODE] = "inode mode",
	[ID_INODE_SIZE] = "inode size",
	[ID_FSMAGIC] = "filesystem magic",
	[ID_OBJ_LABEL] = "object label",
	[ID_CAPS] = "capabilities",
};

struct list_struct *compact_list_init(struct list_head *head,
				      enum compact_types type, u16 modifiers,
				      enum hash_algo algo, bool tlv)
{
	struct list_struct *list;

	list_for_each_entry(list, head, list) {
		if (list->hdr->type == type &&
		    list->hdr->modifiers == modifiers &&
		    list->hdr->algo == algo)
			return list;
	}

	list = malloc(sizeof(*list));
	if (!list)
		return list;

	list->hdr = mmap(NULL, COMPACT_LIST_SIZE_MAX, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (list->hdr == MAP_FAILED) {
		printf("Cannot allocate buffer\n");
		free(list);
		return NULL;
	}

	list->hdr->version = tlv ? 2 : 1;
	list->hdr->type = type;
	list->hdr->modifiers = modifiers;
	list->hdr->algo = algo;
	list->hdr->count = 0;
	list->hdr->datalen = 0;
	list_add_tail(&list->list, head);

	return list;
}

int compact_list_add_digest(int fd, struct list_struct *list, u8 *digest)
{
	struct compact_list_hdr *hdr = list->hdr;
	int digest_len = hash_digest_size[hdr->algo];
	void *ptr;

	ptr = (void *)hdr + sizeof(*hdr) + hdr->datalen;

	memcpy(ptr, digest, digest_len);
	hdr->datalen += digest_len;
	hdr->count++;

	if (hdr->datalen + digest_len < COMPACT_LIST_SIZE_MAX)
		return 0;

	return compact_list_upload(fd, list);
}

int compact_list_tlv_add_digest(int fd, struct list_struct *list,
				struct list_head *head, u8 *digest,
				enum tlv_ids id)
{
	struct compact_list_hdr *hdr = list->hdr;
	int digest_len = hash_digest_size[hdr->algo];

	return compact_list_tlv_add_item(fd, list, head, id, digest_len,
					 digest);
}

int compact_list_tlv_add_metadata(int fd, struct list_struct *list,
				  struct list_head *head, char *path,
				  char *alt_root, struct stat *st,
				  char *obj_label, int obj_label_len,
				  u8 *caps_bin, int caps_bin_len)
{
	struct stat s;
	u32 inode_metadata[4];
	u64 fs_magic;
	struct statfs sfsb;
	char *caps;
	cap_t c, r;
	int alt_root_len = alt_root ? strlen(alt_root) : 0;
	int rc, i;

	sfsb.f_type = 0;

	if (!st) {
		if (stat(path, &s) == -1)
			return -EACCES;

		st = &s;

		if (statfs(path, &sfsb) == -1)
			return -EACCES;
	}

	rc = compact_list_tlv_add_item(fd, list, head, ID_PATH,
				       strlen(path) + 1 - alt_root_len,
				       (u8 *)path + alt_root_len);
	if (rc < 0)
		return rc;

	if (obj_label_len) {
		rc = compact_list_tlv_add_item(fd, list, head, ID_OBJ_LABEL,
					       obj_label_len, (u8 *)obj_label);
		if (rc < 0)
			return rc;
	}

	if (caps_bin_len) {
		c = cap_init();

		r = _fcaps_load((struct vfs_cap_data *)caps_bin, c,
				caps_bin_len);
		if (!r) {
			cap_free(c);
			return -EINVAL;
		}

		caps = cap_to_text(r, NULL);
		cap_free(c);

		if (!caps)
			return -EINVAL;

		rc = compact_list_tlv_add_item(fd, list, head, ID_CAPS,
					       strlen(caps) + 1, (u8 *)caps);

		cap_free(caps);

		if (rc < 0)
			return rc;
	}

	inode_metadata[0] = st->st_uid;
	inode_metadata[1] = st->st_gid;
	inode_metadata[2] = st->st_mode;
	inode_metadata[3] = st->st_size;

	for (i = 0; i < 4; i++) {
		if (ima_canonical_fmt)
			inode_metadata[i] = cpu_to_le32(inode_metadata[i]);

		rc = compact_list_tlv_add_item(fd, list, head, ID_INODE_UID + i,
					sizeof(u32), (u8 *)&inode_metadata[i]);
		if (rc < 0)
			return rc;
	}

	fs_magic = sfsb.f_type;
	if (ima_canonical_fmt)
		fs_magic = cpu_to_le64(fs_magic);

	rc = compact_list_tlv_add_item(fd, list, head, ID_FSMAGIC, sizeof(u64),
				       (u8 *)&fs_magic);
	if (rc < 0)
		return rc;

	return 0;
}

int compact_list_tlv_add_item(int fd, struct list_struct *list,
			      struct list_head *head, enum tlv_ids id,
			      size_t len, u8 *data)
{
	struct tlv_item *cur, *new_item;

	list_for_each_entry(cur, head, list)
		if (cur->item->id == id)
			return -EEXIST;

	new_item = malloc(sizeof(*new_item));
	if (!new_item)
		return -ENOMEM;

	new_item->item = malloc(sizeof(*new_item->item) + len);
	if (!new_item->item) {
		free(new_item);
		return -ENOMEM;
	}

	new_item->item->id = id;
	new_item->item->len = len;
	memcpy(new_item->item->data, data, len);

	list_add_tail(&new_item->list, head);
	return 0;
}

int compact_list_tlv_add_items(int fd, struct list_struct *list,
			       struct list_head *head)
{
	struct compact_list_hdr *hdr = list->hdr;
	struct tlv_item *cur;
	size_t items_len = 0;
	u8 count = 0;
	u8 *ptr;
	int rc = 0;

	list_for_each_entry(cur, head, list) {
		items_len += (sizeof(u8) + sizeof(u32) + cur->item->len);
		count++;
	}

	if (items_len > COMPACT_LIST_SIZE_MAX - sizeof(*hdr)) {
		rc = -EINVAL;
		goto out;
	}

	ptr = (void *)hdr + sizeof(*hdr) + hdr->datalen;
	if (hdr->datalen + sizeof(u8) + items_len > COMPACT_LIST_SIZE_MAX) {
		rc = compact_list_upload(fd, list);
		if (rc)
			goto out;

		return compact_list_tlv_add_items(fd, list, head);
	}

	*ptr++ = count;

	list_for_each_entry(cur, head, list) {
		*ptr++ = cur->item->id;

		if (ima_canonical_fmt)
			cur->item->len = cpu_to_be32(cur->item->len);

		memcpy(ptr, &cur->item->len, sizeof(cur->item->len));
		ptr += sizeof(cur->item->len);
		memcpy(ptr, cur->item->data, cur->item->len);
		ptr += cur->item->len;
	}

	hdr->datalen += sizeof(u8) + items_len;
	hdr->count++;
out:
	return rc;
}

static void hexdump(u8 *buf, int len)
{
	while (--len >= 0)
		printf("%02x", *buf++);
}

void compact_list_tlv_dump_items(struct _tlv_item **items)
{
	u32 u32_value;
	u64 u64_value;
	int i;

	for (i = 0; i < ID__LAST; i++) {
		if (!items[i])
			continue;

		if (i)
			printf("|");

		printf("%s: ", compact_list_tlv_ids[i]);

		switch(i) {
		case ID_DIGEST:
		case ID_EVM_DIGEST:
			hexdump(items[i]->data, items[i]->len);
			break;
		case ID_PATH:
		case ID_OBJ_LABEL:
		case ID_CAPS:
			printf("%s", (char *)items[i]->data);
			break;
		case ID_INODE_UID:
		case ID_INODE_GID:
		case ID_INODE_MODE:
		case ID_INODE_SIZE:
			u32_value = *(u32 *)items[i]->data;
			u32_value = le32_to_cpu(u32_value);
			printf("%u", u32_value);
			break;
		case ID_FSMAGIC:
			u64_value = *(u64 *)items[i]->data;
			u64_value = le64_to_cpu(u64_value);
			printf("%lu", u64_value);
			break;
		default:
			break;
		}
	}

	printf("\n");

}

void compact_list_tlv_free_items(struct list_head *head)
{
	struct tlv_item *p, *q;

	list_for_each_entry_safe(p, q, head, list) {
		list_del(&p->list);
		free(p->item);
		free(p);
	}
}

int compact_list_upload(int fd, struct list_struct *list)
{
	struct compact_list_hdr *hdr = list->hdr;
	struct compact_list_hdr h = { .version = hdr->version,
				      .type = hdr->type,
				      .modifiers = hdr->modifiers,
				      .algo = hdr->algo,
				      .count = 0,
				      .datalen = 0 };
	u32 datalen;
	int ret;

	if (fd < 0)
		return 0;

	hdr = list->hdr;
	datalen = hdr->datalen;

	if (!datalen)
		return 0;

	if (ima_canonical_fmt) {
		hdr->type = cpu_to_le16(hdr->type);
		hdr->modifiers = cpu_to_le16(hdr->modifiers);
		hdr->algo = cpu_to_le16(hdr->algo);
		hdr->count = cpu_to_le32(hdr->count);
		hdr->datalen = cpu_to_le32(hdr->datalen);
	}

	ret = write_check(fd, (void *)hdr, sizeof(*hdr) + datalen);
	memcpy(hdr, &h, sizeof(h));
	return ret;
}

int compact_list_flush_all(int fd, struct list_head *head)
{
	struct list_struct *p, *q;
	int ret = 0;

	list_for_each_entry_safe(p, q, head, list) {
		if (!ret && fd > 0)
			ret = compact_list_upload(fd, p);

		munmap(p->hdr, COMPACT_LIST_SIZE_MAX);
		list_del(&p->list);
		free(p);
	}

	return ret;
}

int gen_filename_prefix(char *filename, int filename_len, int pos,
			const char *format, enum compact_types type)
{
	return snprintf(filename, filename_len, "%d-%s_list-%s-",
			(pos >= 0) ? pos : 0, compact_types_str[type], format);
}

static int filter_lists_common(const struct dirent *file,
			       enum compact_types type)
{
	const char *filename = file->d_name;
	char id_str[NAME_MAX + 1];
	unsigned long pos;
	char *ptr;

	pos = strtoul(filename, &ptr, 10);
	if (pos < 0)
		return 0;

	snprintf(id_str, sizeof(id_str), "-%s_list-", compact_types_str[type]);

	if (strncmp(ptr, id_str, strlen(id_str)))
		return 0;

	if (!strncmp(filename + strlen(filename) - 4, ".sig", 4))
		return 0;

	return 1;
}

int filter_key_lists(const struct dirent *file)
{
	return filter_lists_common(file, COMPACT_KEY);
}

int filter_parser_lists(const struct dirent *file)
{
	return filter_lists_common(file, COMPACT_PARSER);
}

int filter_parser_list_symlink(const struct dirent *file)
{
	if (file->d_type == DT_LNK &&
	    !strncmp(file->d_name, "compact-", 8))
		return 1;

	return 0;
}

int filter_file_lists(const struct dirent *file)
{
	return filter_lists_common(file, COMPACT_FILE);
}

int filter_metadata_lists(const struct dirent *file)
{
	return filter_lists_common(file, COMPACT_METADATA);
}

filter_lists filter[COMPACT__LAST] = {
	[COMPACT_KEY] = filter_key_lists,
	[COMPACT_PARSER] = filter_parser_lists,
	[COMPACT_FILE] = filter_file_lists,
	[COMPACT_METADATA] = filter_metadata_lists,
};

int get_digest_lists(int dirfd, enum compact_types type, struct list_head *head)
{
	struct dirent **digest_lists;
	int ret = 0, i, n;

	n = scandirat(dirfd, ".", &digest_lists, filter[type], compare_lists);
	if (n == -1) {
		printf("Unable to access digest lists\n");
		return -EACCES;
	}

	for (i = 0; i < n; i++) {
		if (!ret)
			ret = add_path_struct(digest_lists[i]->d_name, NULL,
					      head);

		free(digest_lists[i]);
	}

	free(digest_lists);
	return ret;
}

int compare_lists(const struct dirent **e1, const struct dirent **e2)
{
	unsigned long v1 = strtoul((*e1)->d_name, NULL, 10);
	unsigned long v2 = strtoul((*e2)->d_name, NULL, 10);

	return v1 - v2;
}

static int key_upload(int dirfd, char *key_filename)
{
	key_serial_t ima_keyring;
	void *buf;
	loff_t size;
	int ret;

	ima_keyring = syscall(__NR_request_key, "keyring", "_ima",
				NULL, KEY_SPEC_USER_KEYRING);
	if (!ima_keyring) {
		ima_keyring = syscall(__NR_add_key, "keyring", "_ima",
				NULL, 0, KEY_SPEC_USER_KEYRING);
		if (ima_keyring == -1)
			return -EPERM;
	}

	ret = read_file_from_path(dirfd, key_filename, &buf, &size);
	if (ret)
		return ret;

	return syscall(__NR_add_key, "asymmetric", NULL, buf, size,
		       ima_keyring);
}

int digest_list_add_metadata(int dirfd, int fd, char *digest_list_filename,
			     char *digest_lists_dir, struct list_head *head,
			     u8 *digest_list_buf, size_t digest_list_buf_len)
{
	u8 ima_digest[SHA512_DIGEST_SIZE];
	u8 evm_digest[SHA512_DIGEST_SIZE];
	char path[PATH_MAX];
	struct list_struct *list;
	LIST_HEAD(keys);
	struct key_struct *k;
	struct stat st;
	enum hash_algo algo, evm_algo = HASH_ALGO_SHA256;
	u8 *buf, *key_id, *sig;
	char *obj_label = NULL;
	size_t buf_len, keyid_len, sig_len;
	int ret;

        fd = openat(dirfd, digest_list_filename, O_RDONLY);
        if (fd < 0) {
                printf("Cannot open %s\n", digest_list_filename);
                return fd;
        }

        ret = fgetxattr(fd, XATTR_NAME_EVM, NULL, 0);
        close(fd);
	if (ret > 0)
		return 0;

	ret = read_ima_xattr(dirfd, digest_list_filename, &buf, &buf_len,
			     &key_id, &keyid_len, &sig, &sig_len, &algo);
	if (ret < 0)
		return ret;

	if (!sig_len)
		return 0;

	ret = calc_digest(ima_digest, digest_list_buf, digest_list_buf_len,
			  algo);
	if (ret < 0)
		goto out;

	k = new_key(&keys, -1, IMA_KEY_PATH, NULL, false);
	if (!k) {
		ret = -EINVAL;
		goto out;
	}

	ret = verify_sig(&keys, dirfd, buf, buf_len, ima_digest, algo);
	if (ret < 0)
		goto out_key;

	list = compact_list_init(head, COMPACT_METADATA,
				 (1 << COMPACT_MOD_IMMUTABLE), evm_algo, false);
	if (!list)
		goto out_key;

	snprintf(path, sizeof(path), "%s/%s", digest_lists_dir,
		 digest_list_filename);

	if (stat(path, &st) == -1)
		goto out_key;

	ret = get_selinux_label(path, NULL, &obj_label, st.st_mode);
	if (ret < 0)
		goto out_key;

	ret = evm_calc_hmac_or_hash(evm_algo, evm_digest,
				    obj_label ? strlen(obj_label) + 1 : 0,
				    obj_label, buf_len, buf, 0, NULL, 0, 0,
				    st.st_mode);
	if (ret < 0)
		goto out_key;

	ret = compact_list_add_digest(fd, list, evm_digest);
out_key:
	free_keys(&keys);
out:
	free(obj_label);
	free(buf);
	return ret;
}

int digest_list_upload(int dirfd, int fd, struct list_head *head,
		       struct list_head *parser_lib_head,
		       char *digest_list_filename, enum parser_ops op,
		       char *digest_lists_dir)
{
	char *list_id, *format_start, *format_end;
	struct lib *parser;
	void *buf;
	loff_t size;
	int ret;

	list_id = strchr(digest_list_filename, '-');
	if (!list_id++)
		return -EINVAL;

	format_start = strchr(list_id, '-');
	if (!format_start++)
		return -EINVAL;

	format_end = strchr(format_start + 1, '-');
	if (!format_end)
		return -EINVAL;

	ret = read_file_from_path(dirfd, digest_list_filename, &buf, &size);
	if (ret)
		return ret;

	if (!strncmp(format_start, "compact", format_end - format_start) &&
	    *format_end == '-') {
		if (op == PARSER_OP_ADD_META_DIGEST)
			goto out_add_metadata;

		if (fd >= 0) {
			ret = write_check(fd, buf, size);
		} else {
			ret = ima_parse_compact_list(size, buf,
				(op == PARSER_OP_ADD_DIGEST_TO_HTABLE ||
				 op == PARSER_OP_ADD_META_DIGEST_TO_HTABLE) ?
				ima_add_digest_data_entry_kernel : default_func,
				NULL);
			if (ret == size)
				ret = 0;
		}
		goto out_add_metadata;
	}

	parser = lookup_lib(parser_lib_head, "parser",
			    format_start, format_end - format_start);
	if (!parser) {
		printf("Cannot find a parser for %s\n", digest_list_filename);
		ret = -ENOENT;
		goto out;
	}

	ret = ((parser_func)parser->func)(fd, head, size, buf, op);
out_add_metadata:
	if (ret < 0)
		goto out;

	if (op == PARSER_OP_ADD_META_DIGEST)
		ret = digest_list_add_metadata(dirfd, fd, digest_list_filename,
					       digest_lists_dir, head, buf,
					       size);
out:
	munmap(buf, size);
	return ret;
}

int process_lists(int dirfd, int fd, int save, int verbose,
		  struct list_head *head, enum compact_types type,
		  enum parser_ops op, char *digest_lists_dir, char *filename)
{
	struct dirent **digest_lists;
	LIST_HEAD(parser_lib_head);
	struct key_struct *k;
	char path[PATH_MAX], path_sig[PATH_MAX];
	u8 digest[SHA512_DIGEST_SIZE];
	u8 xattr[2 + SHA512_DIGEST_SIZE];
	void *sig;
	loff_t sig_len;
	int ret, i, n, xattr_len;

	n = scandirat(dirfd, ".", &digest_lists, filter[type], compare_lists);
	if (n == -1) {
		printf("Unable to access digest lists\n");
		return -EACCES;
	}

	for (i = 0; i < n; i++) {
		if (filename && strcmp(digest_lists[i]->d_name, filename))
			continue;

		if (verbose)
			printf("Processing: %s\n", digest_lists[i]->d_name);

		if (type == COMPACT_KEY) {
			if (save)
				continue;

			if (op == PARSER_OP_VERIFY) {
				k = new_key(head, dirfd,
					    digest_lists[i]->d_name, NULL,
					    false);
				if (!k) {
					ret = -ENOMEM;
					goto out;
				}

				continue;
			}

			ret = key_upload(dirfd, digest_lists[i]->d_name);
			if (ret < 0) {
				printf("Unable to add key from %s\n",
				       digest_lists[i]->d_name);
			}

			continue;
		}

		switch (op) {
		case PARSER_OP_VERIFY:
			ret = verify_file(head, dirfd, digest_lists[i]->d_name);
			break;
		case PARSER_OP_GEN_IMA_LIST:
			ret = ima_generate_entry(dirfd, fd, digest_lists_dir,
						 digest_lists[i]->d_name);
			break;
		case PARSER_OP_REPAIR_META_DIGEST_LISTS:
			snprintf(path, sizeof(path), "%s/%s", digest_lists_dir,
				 digest_lists[i]->d_name);
			snprintf(path_sig, sizeof(path_sig), "%s.sig/%s.sig",
				 digest_lists_dir, digest_lists[i]->d_name);

			ret = read_file_from_path(-1, path_sig, &sig, &sig_len);
			if (ret < 0)
				break;

			ret = lsetxattr(path, XATTR_NAME_EVM, sig, sig_len, 0);

			munmap(sig, sig_len);

			if (ret < 0) {
				printf("Cannot set EVM xattr to %s\n", path);
				break;
			}

			ret = lsetfilecon(path, DIGEST_LIST_LABEL);
			if (ret < 0) {
				printf("Cannot set SELinux label %s to %s\n",
				       DIGEST_LIST_LABEL, path);
				break;
			}

			ret = chmod(path, DIGEST_LIST_MODE);
			if (ret < 0) {
				printf("Cannot set mode %d to %s\n",
				       DIGEST_LIST_MODE, path);
				break;
			}

			ret = calc_file_digest(digest, -1, path,
					       DIGEST_LIST_ALGO);
			if (ret < 0) {
				printf("Cannot calculate digest of %s\n", path);
				break;
			}

			ret = gen_write_ima_xattr(xattr, &xattr_len, path,
						  DIGEST_LIST_ALGO, digest,
						  true, true);
			if (ret < 0)
				printf("Cannot set IMA xattr to %s\n", path);

			break;
		default:
			ret = digest_list_upload(dirfd, fd, head,
						 &parser_lib_head,
						 digest_lists[i]->d_name, op,
						 digest_lists_dir);
			break;
		}

		if (ret)
			printf("Failed to process %s\n",
			       digest_lists[i]->d_name);
	}
out:
	free_libs(&parser_lib_head);
	for (i = 0; i < n; i++)
		free(digest_lists[i]);

	free(digest_lists);
	return 0;
}
