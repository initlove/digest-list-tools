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
 * File: compact.c
 *      Generates compact digest lists.
 */

#include <fts.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/capability.h>

#include "compact_list.h"
#include "selinux.h"
#include "crypto.h"
#include "xattr.h"
#include "evm.h"
#include "cap.h"

#define FORMAT "compact"
#define FORMAT_TLV "compact_tlv"

static int add_file(int dirfd, int fd, char *path, u16 type, u16 modifiers,
		    struct stat *st, struct list_struct *list,
		    struct list_struct *list_file, enum hash_algo algo,
		    enum hash_algo ima_algo, bool tlv, bool gen_list,
		    bool include_lsm_label, bool root_cred, bool set_ima_xattr,
		    bool set_evm_xattr, char *alt_root, char *caps)
{
	cap_t c;
	u8 ima_xattr[2048];
	struct vfs_cap_data rawvfscap;
	u8 ima_digest[SHA512_DIGEST_SIZE];
	u8 evm_digest[SHA512_DIGEST_SIZE];
	u8 *digest = ima_digest;
	char *obj_label = NULL;
	u8 *caps_bin = NULL;
	LIST_HEAD(items);
	struct stat s;
	int gen_ima_xattr = 1;
	int ret, ima_xattr_len, obj_label_len = 0, caps_bin_len = 0;

	if (!S_ISREG(st->st_mode))
		return -ENOENT;

	if (gen_list) {
		ret = write_check(fd, path, strlen(path));
		if (!ret)
			ret = write_check(fd, "\n", 1);

		return ret;
	}

	if (root_cred) {
		memcpy(&s, st, sizeof(s));
		s.st_uid = 0;
		s.st_gid = 0;
		st = &s;
	}

	if (((st->st_mode & S_IXUGO) || !(st->st_mode & S_IWUGO)) &&
	    st->st_size)
		modifiers |= (1 << COMPACT_MOD_IMMUTABLE);

	ret = calc_file_digest(digest, -1, path, algo);
	if (ret < 0) {
		printf("Cannot calculate digest of %s\n", path);
		goto out;
	}

	if (type == COMPACT_METADATA || tlv) {
		ima_xattr_len = getxattr(path, XATTR_NAME_IMA, NULL, 0);
		if (!gen_ima_xattr &&
		    ima_xattr_len > 0 && ima_xattr_len < sizeof(ima_xattr)) {
			ima_xattr_len = getxattr(path, XATTR_NAME_IMA,
						 ima_xattr, ima_xattr_len);
			if (ima_xattr_len)
				gen_ima_xattr = 0;
		}

		if (gen_ima_xattr) {
			ret = gen_write_ima_xattr(ima_xattr, &ima_xattr_len,
				path, algo, ima_digest,
				(modifiers & (1 << COMPACT_MOD_IMMUTABLE)),
				set_ima_xattr);
			if (ret < 0)
				return ret;
		}

		if (set_evm_xattr) {
			ret = write_evm_xattr(path, algo);
			if (ret < 0)
				return ret;
		}

		if (include_lsm_label == 1)
			obj_label_len = getxattr(path, XATTR_NAME_SELINUX,
						 NULL, 0);
		if (obj_label_len > 0) {
			obj_label = malloc(obj_label_len);
			if (!obj_label)
				return -ENOMEM;

			obj_label_len = getxattr(path, XATTR_NAME_SELINUX,
						 obj_label, obj_label_len);
			if (obj_label_len <= 0) {
				ret = -EACCES;
				goto out;
			}
		} else {
			obj_label_len = 0;
		}

		if (include_lsm_label == 2) {
			ret = get_selinux_label(path, alt_root, &obj_label,
						st->st_mode);
			if (!ret && obj_label)
				obj_label_len = strlen(obj_label) + 1;
		}

		if (caps && strlen(caps)) {
			c = cap_from_text(caps);
			if (!c) {
				ret = -ENOMEM;
				goto out;
			}

			ret = _fcaps_save(&rawvfscap, c, &caps_bin_len);
			if (!ret) {
				caps_bin = malloc(caps_bin_len);
				if (!caps_bin) {
					ret = -ENOMEM;
					goto out;
				}

				memcpy(caps_bin, (u8 *)&rawvfscap,
				       caps_bin_len);
			}

			cap_free(c);
		} else {
			caps_bin_len = getxattr(path, XATTR_NAME_CAPS, NULL, 0);
			if (caps_bin_len > 0) {
				caps_bin = malloc(caps_bin_len);
				if (!caps_bin) {
					ret = -ENOMEM;
					goto out;
				}

				caps_bin_len = getxattr(path, XATTR_NAME_CAPS,
							caps_bin, caps_bin_len);
				if (caps_bin_len <= 0) {
					ret = -EACCES;
					goto out;
				}
			} else {
				caps_bin_len = 0;
			}
		}

		ret = evm_calc_hmac_or_hash(algo, evm_digest,
					    obj_label_len, obj_label,
					    ima_xattr_len, ima_xattr,
					    caps_bin_len, caps_bin,
					    st->st_uid, st->st_gid,
					    st->st_mode);
		if (ret < 0)
			goto out;

		if (type == COMPACT_METADATA)
			digest = evm_digest;
	}

	if (!tlv) {
		if (type == COMPACT_METADATA && list_file) {
			ret = compact_list_add_digest(fd, list_file,
						      ima_digest);
			if (ret < 0)
				goto out;
		}

		ret = compact_list_add_digest(fd, list, digest);
		goto out;
	}

	if (type == COMPACT_METADATA) {
		ret = compact_list_tlv_add_digest(fd, list, &items, evm_digest,
						  ID_EVM_DIGEST);
		if (ret < 0)
			goto out_free_items;
	}

	ret = compact_list_tlv_add_digest(fd, list, &items, ima_digest,
					  ID_DIGEST);
	if (ret < 0)
		goto out_free_items;

	ret = compact_list_tlv_add_metadata(fd, list, &items, path, alt_root,
					    st, obj_label, obj_label_len,
					    caps_bin, caps_bin_len);
	if (ret < 0)
		goto out_free_items;

	ret = compact_list_tlv_add_items(fd, list, &items);

	if (ret < 0) {
		printf("Cannot add digest to compact list\n");
		goto out_free_items;
	}

	if (algo != ima_algo && getuid() == 0) {
		ret = write_ima_xattr(-1, path, NULL, 0, NULL, 0, algo);
		if (ret < 0) {
			printf("Cannot write xattr to %s\n", path);
			goto out_free_items;
		}
	}
out_free_items:
	compact_list_tlv_free_items(&items);
out:
	free(obj_label);
	free(caps_bin);
	return ret;
}

int generator(int dirfd, int pos, struct list_head *head_in,
	      struct list_head *head_out, enum compact_types type,
	      u16 modifiers, enum hash_algo algo, enum hash_algo ima_algo,
	      bool tlv, char *alt_root)
{
	char filename[NAME_MAX + 1], *basename = NULL, *link = NULL;
	char path[PATH_MAX], *path_list = NULL, *data_ptr, *line_ptr, *attr_ptr;
	char *path_ptr = NULL, *gen_list_path = NULL;
	struct list_struct *list = NULL, *list_file = NULL;
	struct path_struct *cur, *cur_i, *cur_e;
	LIST_HEAD(list_head);
	FTS *fts = NULL;
	FTSENT *ftsent;
	struct stat st, *statp;
	void *data;
	loff_t size;
	bool unlink = true;
	char *paths[2] = { NULL, NULL };
	char *attrs[ATTR__LAST];
	struct passwd *pwd;
	struct group *grp;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	int include_ima_digests = 0, only_executables = 0, set_ima_xattr = 0;
	int ret = 0, fd, prefix_len, include_lsm_label = 0, include_file = 0;
	int path_list_ext = 0, set_evm_xattr = 0;
	int use_path_list_filename = 0, root_cred = 0, include_path = 0, i;

	list_for_each_entry(cur, head_in, list) {
		if (cur->path[1] != ':') {
			pr_err("Options must be in the format <opt>:<path>\n");
			return -EINVAL;
		}

		if (cur->path[0] == 'i')
			include_ima_digests = 1;
		if (cur->path[0] == 'L')
			path_list = &cur->path[2];
		if (cur->path[0] == 'M')
			path_list_ext = 1;
		if (cur->path[0] == 'G')
			gen_list_path = &cur->path[2];
		if (cur->path[0] == 'l') {
			if (!strcmp(&cur->path[2], "policy"))
				include_lsm_label = 2;
			else
				include_lsm_label = 1;
		}
		if (cur->path[0] == 'e')
			only_executables = 1;
		if (cur->path[0] == 'u')
			use_path_list_filename = 1;
		if (cur->path[0] == 'r')
			root_cred = 1;
		if (cur->path[0] == 'F')
			include_path = 1;
		if (cur->path[0] == 'x') {
			if (!strcmp(&cur->path[2], "evm"))
				set_evm_xattr = 1;
			else
				set_ima_xattr = 1;
		}
	}

	if (path_list) {
		ret = read_file_from_path(-1, path_list, &data, &size);
		if (ret < 0)
			return ret;

		data_ptr = (char *)data;

		while ((line_ptr = strsep(&data_ptr, "\n"))) {
			if (!strlen(line_ptr))
				continue;

			attr_ptr = line_ptr;
			i = 0;

			if (path_list_ext) {
				while (i < ATTR__LAST &&
				       (attrs[i] = strsep(&attr_ptr, "|")))
						i++;
				if (i != ATTR__LAST)
					continue;
			}

			if (stat(line_ptr, &st) == -1 || !S_ISREG(st.st_mode))
				continue;

			snprintf(path, sizeof(path), "I:%s", line_ptr);
			ret = add_path_struct(path, attrs, head_in);
			if (ret < 0)
				return ret;
		}

		path_ptr = path_list;
	}

	list_for_each_entry(cur, head_in, list) {
		if (cur->path[0] != 'I')
			continue;

		if (!use_path_list_filename || !path_list)
			path_ptr = &cur->path[2];
		break;
	}

	if (!path_ptr) {
		printf("Input path not specified\n");
		return -EINVAL;
	}

	if (!gen_list_path) {
		basename = strrchr(path_ptr, '/');
		if (!basename)
			basename = path_ptr;
		else
			basename++;

		prefix_len = gen_filename_prefix(filename, sizeof(filename),
					pos, tlv ? FORMAT_TLV : FORMAT, type);
		snprintf(filename + prefix_len, sizeof(filename) - prefix_len,
			 "%s", basename);
	}

	if (type == COMPACT_METADATA && include_lsm_label) {
		ret = selinux_init_setup();
		if (ret)
			return ret;
	}

	if (!gen_list_path)
		fd = openat(dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	else
		fd = openat(-1, gen_list_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		printf("Cannot open %s\n", filename);
		ret = -EACCES;
		goto out_selinux;
	}

	list = compact_list_init(&list_head, type, modifiers, algo, tlv);
	if (!list)
		goto out_close;

	if (type == COMPACT_METADATA && include_ima_digests) {
		list_file = compact_list_init(&list_head, COMPACT_FILE,
					      modifiers, algo, tlv);
		if (!list_file)
			goto out_close;
	}

	list_for_each_entry(cur, head_in, list) {
		if (cur->path[0] != 'I')
			continue;

		if (path_list_ext) {
			st.st_mode = atoi(cur->attrs[1]);
			st.st_uid = 0;
			pwd = getpwnam(cur->attrs[2]);
			if (pwd)
				st.st_uid = pwd->pw_uid;
			st.st_gid = 0;
			grp = getgrnam(cur->attrs[3]);
			if (grp)
				st.st_gid = grp->gr_gid;
		}

		paths[0] = &cur->path[2];

		fts = fts_open(paths, fts_flags, NULL);
		if (!fts) {
			ret = -EACCES;
			goto out_close;
		}

		while ((ftsent = fts_read(fts)) != NULL) {
			switch (ftsent->fts_info) {
			case FTS_F:
				include_file = 0;
				statp = ftsent->fts_statp;
				if (path_list_ext)
					statp = &st;

				if (include_path && only_executables) {
					list_for_each_entry(cur_i, head_in,
							    list) {
						if (cur_i->path[0] != 'F')
							continue;

						if (!strncmp(ftsent->fts_path,
						    &cur_i->path[2],
						    strlen(&cur_i->path[2]))) {
							include_file = 1;
							break;
						}
					}
				} else {
					if (!only_executables)
						include_file = 1;
				}

				if (only_executables &&
				    (statp->st_mode & S_IXUGO))
					include_file = 1;

				if (!include_file)
					continue;

				include_file = 1;

				list_for_each_entry(cur_e, head_in, list) {
					if (cur_e->path[0] == 'E' &&
					    !strncmp(&cur_e->path[2],
						     ftsent->fts_path,
						     strlen(&cur_e->path[2]))) {
						include_file = 0;
						break;
					}
				}

				if (!include_file)
					continue;

				ret = add_file(dirfd, fd, ftsent->fts_path,
					       type, modifiers, statp, list,
					       list_file, algo, ima_algo, tlv,
					       gen_list_path != NULL,
					       include_lsm_label, root_cred,
					       set_ima_xattr, set_evm_xattr,
					       alt_root, cur->attrs[4]);
				if (!ret)
					unlink = false;
				if (ret < 0 && ret != -ENOENT &&
				    ret != -ENODATA)
					goto out_fts_close;

				break;
			default:
				break;
			}
		}

		fts_close(fts);
		fts = NULL;
	}

	ret = compact_list_flush_all(fd, &list_head);
	if (ret < 0) {
		printf("Cannot write digest list to %s\n", filename);
		goto out_close;
	}

	if (!unlink && !gen_list_path)
		ret = add_path_struct(filename, NULL, head_out);
out_fts_close:
	if (fts)
		fts_close(fts);
out_close:
	close(fd);

	if (ret < 0 || unlink) {
		unlinkat(dirfd, filename, 0);
	} else if (!gen_list_path) {
		if (!tlv && !strcmp(basename, "upload_digest_lists")) {
			link = strchr(strchr(filename, '-') + 1, '-') + 1;
			unlinkat(dirfd, link, 0);
			ret = symlinkat(filename, dirfd, link);
		}
	}
out_selinux:
	if (type == COMPACT_METADATA && include_lsm_label)
		selinux_end_setup();

	return ret;
}
