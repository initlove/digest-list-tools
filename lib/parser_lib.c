/*
 * Copyright (C) 2019-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: parser_lib.c
 *      Parser library.
 */

#include <errno.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/capability.h>

#include "compact_list.h"
#include "parser_lib.h"
#include "crypto.h"
#include "xattr.h"
#include "evm.h"
#include "cap.h"

int add_digest(int fd, struct list_head *head, u16 type, u16 modifiers,
	       u16 algo, u8 *digest)
{
	struct list_struct *list;

	if (!digest) {
		pr_err("TLV compact list, invalid data\n");
		return -ENOENT;
	}

	list = compact_list_init(head, type, modifiers, algo, false);
	if (!list)
		return -ENOMEM;

	return compact_list_add_digest(fd, list, digest);
}

static int create_dirs(char *path)
{
	char *path_ptr = path;
	int ret = 0, path_len;

	while ((path_ptr = strchr(path_ptr, '/'))) {
		if (path_ptr == path) {
			path_ptr++;
			continue;
		}

		path_len = path_ptr - path;
		if (path_len >= PATH_MAX)
			return -EINVAL;

		*path_ptr = '\0';
		ret = mkdir(path, 0700);
		if (ret == -1 && errno == EEXIST)
			ret = 0;
		if (ret < 0)
			return ret;

		*path_ptr++ = '/';
	}

	return ret;
}

int update_digest(u16 algo, u8 *digest, char *src_path, char *backup_dir)
{
	u8 file_digest[SHA512_DIGEST_SIZE];
	char dest_path[PATH_MAX];
	struct stat st;
	int ret;

	if (!digest || !src_path || !backup_dir)
		return -ENOENT;

	if (stat(src_path, &st) == -1)
		return 0;

	ret = calc_file_digest(file_digest, -1, src_path, algo);
	if (ret < 0)
		return ret;

	if (!memcmp(file_digest, digest, hash_digest_size[algo]))
		return 0;

	memcpy(digest, file_digest, hash_digest_size[algo]);

	snprintf(dest_path, sizeof(dest_path), "%s.orig/%s", backup_dir,
		 src_path);

	ret = create_dirs(dest_path);
	if (ret < 0)
		return ret;

	return copy_file(src_path, dest_path);
}

int restore_files(char *orig_path, char *backup_dir)
{
	char backup_orig_path[PATH_MAX];
	char backup_path[PATH_MAX];
	struct stat st;
	int ret;

	if (!orig_path || !backup_dir)
		return -ENOENT;

	snprintf(backup_orig_path, sizeof(backup_orig_path), "%s.orig/%s",
		 backup_dir, orig_path);
	if (stat(backup_orig_path, &st) == -1)
		return 0;

	snprintf(backup_path, sizeof(backup_path), "%s/%s", backup_dir,
		 orig_path);

	ret = create_dirs(backup_path);
	if (ret < 0)
		return ret;

	ret = copy_file(orig_path, backup_path);
	if (ret < 0)
		return ret;

	return copy_file(backup_orig_path, orig_path);
}

int calc_metadata_digest(int fd, struct list_head *head, u16 type,
			 u16 modifiers, u16 algo, u8 *digest, u8 *evm_digest,
			 char *path, uid_t uid, gid_t gid, mode_t mode,
			 char *obj_label, char *caps)
{
	cap_t c;
	struct vfs_cap_data rawvfscap;
	enum hash_algo evm_algo = HASH_ALGO_SHA256;
	u8 ima_xattr[2 + SHA512_DIGEST_SIZE], *caps_bin = NULL;
	int ret, ima_xattr_len, rawvfscap_len = 0;

	if (!digest || !path) {
		pr_err("TLV compact list, missing data\n");
		return -ENOENT;
	}

	ret = gen_write_ima_xattr(ima_xattr, &ima_xattr_len, path, algo, digest,
				  (modifiers & (1 << COMPACT_MOD_IMMUTABLE)),
				  false);
	if (ret < 0)
		return ret;

	if (ima_canonical_fmt) {
		uid = le32_to_cpu(uid);
		gid = le32_to_cpu(gid);
		mode = le32_to_cpu(mode);
	}

	if (caps) {
		c = cap_from_text(caps);
		if (!c)
			return -EINVAL;

		ret = _fcaps_save(&rawvfscap, c, &rawvfscap_len);

		cap_free(c);

		if (ret < 0)
			return -EINVAL;
	}

	ret = evm_calc_hmac_or_hash(evm_algo, evm_digest,
				    obj_label ? strlen(obj_label) + 1 : 0,
				    obj_label, ima_xattr_len, ima_xattr,
				    rawvfscap_len, (u8 *)&rawvfscap,
				    uid, gid, mode);
	if (ret == -ENOENT)
		ret = 0;

	free(caps_bin);
	return ret;
}

int add_metadata_digest(int fd, struct list_head *head, u16 modifiers, u8 *evm_digest)
{
	enum hash_algo evm_algo = HASH_ALGO_SHA256;
	struct list_struct *list_metadata;

	list_metadata = compact_list_init(head, COMPACT_METADATA, modifiers, evm_algo,
					  false);
	if (!list_metadata)
		return -ENOMEM;

	return compact_list_add_digest(fd, list_metadata, evm_digest);
}

int add_ima_xattr(int fd, struct list_head *head, u16 type, u16 modifiers,
		  u16 algo, u8 *digest, char *path)
{
	u8 ima_xattr[2 + SHA512_DIGEST_SIZE];
	int ret, ima_xattr_len;

	if (!digest || !path) {
		pr_err("TLV compact list, missing data\n");
		return -ENOENT;
	}

	ret = gen_write_ima_xattr(ima_xattr, &ima_xattr_len, path, algo, digest,
				  (modifiers & (1 << COMPACT_MOD_IMMUTABLE)),
				  true);
	if (ret < 0)
		pr_err("Cannot set IMA xattr for %s\n", path);

	return 0;
}

int check_repair_xattr(char *path, char *xattr_name, void *xattr_value,
		       int xattr_value_len, int ima_algo, int modifiers,
		       int repair)
{
	cap_t c;
	struct vfs_cap_data rawvfscap;
	void *cur_xattr_value = NULL;
	int cur_xattr_value_len;
	u8 ima_xattr[2 + SHA512_DIGEST_SIZE];
	int ret, rawvfscap_len, ima_xattr_len;

	if (!strcmp(xattr_name, XATTR_NAME_IMA)) {
		ret = gen_write_ima_xattr(ima_xattr, &ima_xattr_len, path,
				  ima_algo, xattr_value,
                                  (modifiers & (1 << COMPACT_MOD_IMMUTABLE)),
                                  false);
		if (ret < 0)
			return ret;

		xattr_value = &ima_xattr;
		xattr_value_len = ima_xattr_len;
	} else if (!strcmp(xattr_name, XATTR_NAME_CAPS) && xattr_value_len) {
		c = cap_from_text(xattr_value);
		if (!c)
			return -EINVAL;

		ret = _fcaps_save(&rawvfscap, c, &rawvfscap_len);

		cap_free(c);

		if (ret < 0)
			return -EINVAL;

		xattr_value = &rawvfscap;
		xattr_value_len = rawvfscap_len;
        }

	cur_xattr_value_len = lgetxattr(path, xattr_name, NULL, 0);
	if (((cur_xattr_value_len == -1 && errno == ENODATA) ||
	    cur_xattr_value_len == 0) && !xattr_value_len)
		return 0;

	if (cur_xattr_value_len == -1 && errno != ENODATA) {
		pr_err("Path %s: cannot read %s xattr\n", path, xattr_name);
		return cur_xattr_value_len;
	}

	if (!xattr_value_len) {
		pr_err("Path %s: %s xattr defined, it should be removed\n",
		       path, xattr_name);

		if (repair) {
			ret = lremovexattr(path, xattr_name);
			if (ret < 0) {
				printf("Path: %s, cannot remove %s xattr\n",
				       path, xattr_name);
			}
		}

		return 0;
	}

	if (cur_xattr_value_len > 0) {
		cur_xattr_value = malloc(cur_xattr_value_len);
		if (!cur_xattr_value) {
			pr_err("Out of memory\n");
			return -ENOMEM;
		}
	}

	cur_xattr_value_len = lgetxattr(path, xattr_name, cur_xattr_value,
					cur_xattr_value_len);
	if (xattr_value_len != cur_xattr_value_len ||
	    memcmp(xattr_value, cur_xattr_value, xattr_value_len)) {
		pr_err("Path %s: %s xattr value mismatch\n", path, xattr_name);

		if (repair) {
			ret = lsetxattr(path, xattr_name, xattr_value,
					xattr_value_len, 0);
			if (ret) {
				pr_err("Path %s: failed to set %s xattr\n",
				       path, xattr_name);
				goto out;
			}
		}
	}

	ret = 0;
out:
	free(cur_xattr_value);
	return ret;
}

int check_repair_attr(char *path, uid_t uid, gid_t gid, mode_t mode,
		      int repair)
{
	struct stat st;
	int ret;

	if (stat(path, &st) == -1) {
		pr_err("Path %s: file does not exist\n", path);
		return -ENOENT;
	}

	if (uid != st.st_uid || gid != st.st_gid) {
		if (uid != st.st_uid)
			pr_err("Path %s: uid mismatch, expected: %d, "
			       "current: %d\n", path, uid, st.st_uid);

		if (gid != st.st_gid)
			pr_err("Path %s: gid mismatch, expected: %d, "
			       "current: %d\n", path, gid, st.st_gid);

		if (repair) {
			ret = chown(path, uid, gid);
			if (ret < 0) {
				pr_err("Path %s: cannot set uid/gid\n", path);
				return ret;
			}
		}
	}

	if (mode != st.st_mode) {
		pr_err("Path %s: mode mismatch, expected: %d, current: %d\n",
		       path, mode, st.st_mode);

		if (repair) {
			ret = chmod(path, mode);
			if (ret < 0) {
				pr_err("Path %s: cannot set mode\n", path);
				return ret;
			}
		}
	}

	return 0;
}
