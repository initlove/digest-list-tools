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
 *      Generate RPM digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <fts.h>

#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>
#include <sys/capability.h>

#include "compact_list.h"
#include "selinux.h"
#include "crypto.h"
#include "xattr.h"
#include "evm.h"
#include "cap.h"

#define FORMAT "rpm"

const unsigned char rpm_header_magic[8] = {
	0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
};

static int add_file(int dirfd, char *filename, Header *hdr, u16 type,
		    u16 modifiers, struct list_head *head_in,
		    struct list_head *head_out, enum hash_algo algo,
		    enum hash_algo ima_algo, bool tlv, bool include_ima_digests,
		    bool include_lsm_label, bool only_executables,
		    bool include_path, bool set_ima_xattr, int set_evm_xattr,
		    char *alt_root)
{
	const char *ima_digest_str, *filecaps_str, *basename, *dirname;
	enum pgp_hash_algo pgp_algo;
	char file_path[PATH_MAX];
	u8 ima_xattr[2048];
	u8 ima_digest[SHA512_DIGEST_SIZE];
	u8 evm_digest[SHA512_DIGEST_SIZE];
	LIST_HEAD(list_head);
	u8 *digest;
	char *obj_label = NULL;
	LIST_HEAD(items);
	int ret = 0, ima_xattr_len, obj_label_len = 0, include_file = 0;
	rpmtd filedigestalgo, filedigests, filemodes, filesizes, filecaps;
	rpmtd basenames, dirnames, dirindexes;
	struct path_struct *cur;
	uint16_t mode;
	uint32_t size, dirindex;
	u16 file_modifiers;
	cap_t c;
	struct vfs_cap_data rawvfscap;
	int rawvfscap_len, fd;
	struct list_struct *list = NULL, *list_file = NULL;
	struct stat s;

	fd = openat(dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -EACCES;

	filedigestalgo = rpmtdNew();
	headerGet(*hdr, RPMTAG_FILEDIGESTALGO, filedigestalgo, 0);
	filedigests = rpmtdNew();
	headerGet(*hdr, RPMTAG_FILEDIGESTS, filedigests, 0);
	filemodes = rpmtdNew();
	headerGet(*hdr, RPMTAG_FILEMODES, filemodes, 0);
	filesizes = rpmtdNew();
	headerGet(*hdr, RPMTAG_FILESIZES, filesizes, 0);
	filecaps = rpmtdNew();
	headerGet(*hdr, RPMTAG_FILECAPS, filecaps, 0);
	basenames = rpmtdNew();
	headerGet(*hdr, RPMTAG_BASENAMES, basenames, 0);
	dirnames = rpmtdNew();
	headerGet(*hdr, RPMTAG_DIRNAMES, dirnames, 0);
	dirindexes = rpmtdNew();
	headerGet(*hdr, RPMTAG_DIRINDEXES, dirindexes, 0);

	pgp_algo = PGP_HASH_MD5;
	if (rpmtdGetUint32(filedigestalgo))
		pgp_algo = *rpmtdGetUint32(filedigestalgo);

	if (pgp_algo >= PGP_HASH__LAST) {
		ret = -EINVAL;
		goto out_close;
	}

	algo = pgp_algo_mapping[pgp_algo];
	list = compact_list_init(&list_head, type, modifiers, algo, tlv);
	if (!list)
		goto out_close;

	if (type == COMPACT_METADATA && include_ima_digests) {
		list_file = compact_list_init(&list_head, COMPACT_FILE,
					      modifiers, algo, tlv);
		if (!list_file)
			goto out_close;
	}

	while ((ima_digest_str = rpmtdNextString(filedigests))) {
		include_file = 0;
		ret = 0;

		rpmtdNext(filemodes);
		mode = *rpmtdGetUint16(filemodes);
		size = *rpmtdNextUint32(filesizes);
		filecaps_str = rpmtdNextString(filecaps);
		basename = rpmtdNextString(basenames);
		dirindex = *rpmtdNextUint32(dirindexes);

		rpmtdSetIndex(dirnames, dirindex);
		dirname = rpmtdGetString(dirnames);

		snprintf(file_path, sizeof(file_path), "%s%s", dirname,
			 basename);

		if (!strlen(ima_digest_str))
			continue;

		hex2bin(ima_digest, ima_digest_str, hash_digest_size[algo]);
		digest = ima_digest;

		if (!S_ISREG(mode))
			continue;

		if (include_path && only_executables) {
			list_for_each_entry(cur, head_in, list) {
				if (cur->path[0] != 'F')
					continue;

				if (!strncmp(file_path, &cur->path[2],
					     strlen(&cur->path[2]))) {
					include_file = 1;
					break;
				}
			}
		} else {
			if (!only_executables)
				include_file = 1;
		}

		if (only_executables && (mode & (S_IXUGO | S_ISUID | S_ISVTX)))
			include_file = 1;

		if (!include_file)
			continue;

		if (type == COMPACT_METADATA) {
			file_modifiers = modifiers;
			if (((mode & S_IXUGO) ||
			    !(mode & S_IWUGO)) && size)
			    file_modifiers |= (1 << COMPACT_MOD_IMMUTABLE);

			ret = gen_write_ima_xattr(ima_xattr, &ima_xattr_len,
				file_path, algo, ima_digest,
				(file_modifiers & (1 << COMPACT_MOD_IMMUTABLE)),
				set_ima_xattr);
			if (ret < 0)
				goto out_close;

			if (set_evm_xattr) {
				ret = write_evm_xattr(file_path, algo);
				if (ret < 0)
					return ret;
			}

			if (include_lsm_label) {
				ret = get_selinux_label(file_path, alt_root,
							&obj_label, mode);
				if (ret < 0)
					goto out_close;

				obj_label_len = strlen(obj_label) + 1;
			}

			if (filecaps_str && strlen(filecaps_str)) {
				c = cap_from_text(filecaps_str);
				if (!c) {
					ret = -EINVAL;
					goto out_close;
				}

				ret = _fcaps_save(&rawvfscap, c,
						  &rawvfscap_len);
				cap_free(c);

				if (ret < 0)
					goto out_close;
			} else {
				rawvfscap_len = 0;
			}

			ret = evm_calc_hmac_or_hash(algo,
					evm_digest, obj_label_len, obj_label,
					ima_xattr_len, ima_xattr,
					rawvfscap_len, (u8 *)&rawvfscap,
					0, 0, mode);
			if (ret < 0)
				goto out_close;

			digest = evm_digest;

			s.st_uid = 0;
			s.st_gid = 0;
			s.st_mode = mode;
			s.st_size = size;
		}

		if (!tlv) {
			if (type == COMPACT_METADATA && include_ima_digests) {
				ret = compact_list_add_digest(fd, list_file,
							      ima_digest);
				if (ret < 0)
					goto out_free_items;
			}

			ret = compact_list_add_digest(fd, list, digest);
			if (ret < 0)
				goto out_free_items;

			continue;
		}

		if (type == COMPACT_METADATA) {
			ret = compact_list_tlv_add_digest(fd, list, &items,
							  evm_digest,
							  ID_EVM_DIGEST);
			if (ret < 0)
				goto out_free_items;
		}

		ret = compact_list_tlv_add_digest(fd, list, &items, ima_digest,
						  ID_DIGEST);
		if (ret < 0)
			goto out_free_items;

		ret = compact_list_tlv_add_metadata(fd, list, &items, file_path,
						    alt_root, &s, obj_label,
						    obj_label_len,
						    (u8 *)&rawvfscap,
						    rawvfscap_len);
		if (ret < 0)
			goto out_free_items;

		ret = compact_list_tlv_add_items(fd, list, &items);
		if (ret < 0) {
			printf("Cannot add digest to compact list\n");
			goto out_free_items;
		}
out_free_items:
		compact_list_tlv_free_items(&items);
	}

	if (!ret) {
		ret = compact_list_flush_all(fd, &list_head);
		if (ret < 0)
			printf("Cannot write digest list to %s\n", filename);
	}
out_close:
	fstat(fd, &s);
	close(fd);

	compact_list_tlv_free_items(&items);
	rpmtdFree(filedigestalgo);
	rpmtdFree(filedigests);
	rpmtdFree(filemodes);
	rpmtdFree(filesizes);
	rpmtdFree(filecaps);
	rpmtdFree(basenames);
	rpmtdFree(dirnames);
	rpmtdFree(dirindexes);
	free(obj_label);

	if (!s.st_size)
		ret = -ENODATA;

	if (ret < 0)
		unlinkat(dirfd, filename, 0);
	else
		ret = add_path_struct(filename, NULL, head_out);

	return ret;
}

static void gen_filename(Header rpm, int pos, enum compact_types type,
			 char *filename, int filename_len, char *output_format)
{
	rpmtd name = rpmtdNew(), version = rpmtdNew();
	rpmtd release = rpmtdNew(), arch = rpmtdNew();
	int prefix_len;

	headerGet(rpm, RPMTAG_NAME, name, 0);
	headerGet(rpm, RPMTAG_VERSION, version, 0);
	headerGet(rpm, RPMTAG_RELEASE, release, 0);
	headerGet(rpm, RPMTAG_ARCH, arch, 0);

	prefix_len = gen_filename_prefix(filename, filename_len, pos,
					 output_format, type);

	snprintf(filename + prefix_len, filename_len - prefix_len,
		 "%s-%s-%s.%s", rpmtdGetString(name), rpmtdGetString(version),
		 rpmtdGetString(release), rpmtdGetString(arch));

	rpmtdFree(name);
	rpmtdFree(version);
	rpmtdFree(release);
	rpmtdFree(arch);
}

static int find_package(Header rpm, char *package)
{
	rpmtd name = rpmtdNew();
	int found = 0;

	headerGet(rpm, RPMTAG_NAME, name, 0);
	if (!strncmp(rpmtdGetString(name), package, strlen(package)))
		found = 1;

	rpmtdFree(name);
	return found;
}

static int gen_rpm_digest_list(Header rpm, int dirfd, char *filename,
			       struct list_head *head_out)
{
	rpmtd immutable;
	ssize_t ret;
	int fd;

	fd = openat(dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return -EACCES;

	ret = write_check(fd, rpm_header_magic, sizeof(rpm_header_magic));
	if (ret < 0)
		goto out;

	immutable = rpmtdNew();
	headerGet(rpm, RPMTAG_HEADERIMMUTABLE, immutable, 0);
	ret = write_check(fd, immutable->data, immutable->count);
	rpmtdFree(immutable);
out:
	close(fd);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);
	else
		ret = add_path_struct(filename, NULL, head_out);

	return ret;
}

static int find_file(struct list_head *head, char *filename)
{
	struct path_struct *cur;
	char *filename_ptr, *cur_path_ptr;

	if (list_empty(head))
		return 0;

	list_for_each_entry(cur, head, list) {
		cur_path_ptr = strchr(cur->path, '-') + 1;
		cur_path_ptr = strchr(cur_path_ptr, '-') + 1;

		filename_ptr = strchr(filename, '-') + 1;
		filename_ptr = strchr(filename_ptr, '-') + 1;

		if (!strcmp(cur_path_ptr, filename))
			return 1;
	}

	return 0;
}

static int parse_options(struct list_head *head_in, bool tlv,
			 int *include_ima_digests, int *include_lsm_label,
			 int *only_executables, int *include_path,
			 char **output_format, char **package,
			 int *set_ima_xattr, int *set_evm_xattr)
{
	struct path_struct *cur;

	list_for_each_entry(cur, head_in, list) {
		if (cur->path[1] != ':') {
			pr_err("Options must be in the format <opt>:<path>\n");
			return -EINVAL;
		}

		if (cur->path[0] == 'i')
			*include_ima_digests = 1;
		if (cur->path[0] == 'F')
			*include_path = 1;
		if (cur->path[0] == 'l')
			*include_lsm_label = 1;
		if (cur->path[0] == 'e')
			*only_executables = 1;
		if (cur->path[0] == 'f')
			*output_format = &cur->path[2];
		if (cur->path[0] == 'p')
			*package = &cur->path[2];
		if (cur->path[0] == 'x') {
			if (!strcmp(&cur->path[2], "evm"))
				*set_evm_xattr = 1;
			else
				*set_ima_xattr = 1;
		}
	}

	if (!strcmp(*output_format, "compact") && tlv) {
		pr_err("Compact TLV must be selected\n");
		return -EINVAL;
	}

	return 0;
}

int db_generator(int dirfd, int pos, struct list_head *head_in,
		 struct list_head *head_out, enum compact_types type,
		 u16 modifiers, enum hash_algo algo, enum hash_algo ima_algo,
		 bool tlv, char *alt_root)
{
	char filename[NAME_MAX + 1];
	rpmts ts = NULL;
	Header hdr;
	rpmdbMatchIterator mi;
	LIST_HEAD(digest_list_head);
	int include_ima_digests = 0, include_lsm_label = 0, set_evm_xattr = 0;
	int only_executables = 0, include_path = 0, set_ima_xattr = 0;
	char *output_format = FORMAT;
	char *package = NULL;
	int ret;

	ret = parse_options(head_in, tlv, &include_ima_digests,
			    &include_lsm_label, &only_executables,
			    &include_path, &output_format, &package,
			    &set_ima_xattr, &set_evm_xattr);
	if (ret < 0)
		return ret;

	ret = get_digest_lists(dirfd, type, &digest_list_head);
	if (ret < 0)
		goto out;

	ts = rpmtsCreate();
	if (!ts) {
		rpmlog(RPMLOG_NOTICE, "rpmtsCreate() error..\n");
		ret = -EACCES;
		goto out;
	}

	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		ret = -EACCES;
		goto out;
	}

	if (!strncmp(output_format, "compact", 7)) {
		if (include_lsm_label) {
			ret = selinux_init_setup();
			if (ret)
				return ret;
		}

		if (!strcmp(output_format, "compact_tlv"))
			tlv = true;
	}

	mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
	while ((hdr = rpmdbNextIterator(mi)) != NULL) {
		gen_filename(hdr, pos, type, filename, sizeof(filename),
			     output_format);

		if (strstr(filename, "gpg-pubkey") != NULL)
			continue;

		if (find_file(&digest_list_head, filename))
			continue;

		if (package && !find_package(hdr, package))
			continue;

		if (!strncmp(output_format, "compact", 7))
			ret = add_file(dirfd, filename, &hdr, type, modifiers,
				       head_in, head_out, algo, ima_algo, tlv,
				       include_ima_digests, include_lsm_label,
				       only_executables, include_path,
				       set_ima_xattr, set_evm_xattr, alt_root);
		else
			ret = gen_rpm_digest_list(hdr, dirfd, filename,
						  head_out);

		if (ret < 0 && ret != -ENODATA) {
			printf("Cannot generate %s digest list\n", filename);
			break;
		}

		if (!ret && pos >= 0)
			pos++;
	}

	if (ret == -ENODATA)
		ret = 0;

	rpmdbFreeIterator(mi);
	rpmFreeRpmrc();
	rpmtsFree(ts);
out:
	if (!strncmp(output_format, "compact", 7) && include_lsm_label)
		selinux_end_setup();

	free_path_structs(&digest_list_head);
	return ret;
}

static int _pkg_generator(int dirfd, int pos, char *path,
			  struct list_head *head_in, struct list_head *head_out,
			  enum compact_types type, int modifiers,
			  enum hash_algo algo, enum hash_algo ima_algo,
			  bool tlv, char *output_format,
			  int include_ima_digests, int include_lsm_label,
			  int only_executables, int include_path,
			  int set_ima_xattr, int set_evm_xattr, char *alt_root)
{
	char filename[NAME_MAX + 1];
	Header hdr;
	rpmts ts = NULL;
	FD_t fd;
	int ret;
	rpmVSFlags vsflags = 0;

	ts = rpmtsCreate();
	if (!ts) {
		rpmlog(RPMLOG_NOTICE, "rpmtsCreate() error..\n");
		return -EACCES;
	}

	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		ret = -EACCES;
		goto out_ts;
	}

	vsflags |= _RPMVSF_NODIGESTS;
	vsflags |= _RPMVSF_NOSIGNATURES;
	rpmtsSetVSFlags(ts, vsflags);

	fd = Fopen(path, "r.ufdio");
	if ((!fd) || Ferror(fd)) {
		rpmlog(RPMLOG_NOTICE, "Failed to open package file %s, %s\n",
		       path, Fstrerror(fd));
		ret = -EACCES;
		goto out_ts;
	}

	ret = rpmReadPackageFile(ts, fd, "rpm", &hdr);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Could not read package file %s\n", path);
		goto out_fd;
	}

	gen_filename(hdr, pos, type, filename, sizeof(filename), output_format);

	if (!strncmp(output_format, "compact", 7))
		ret = add_file(dirfd, filename, &hdr, type, modifiers,
				head_in, head_out, algo, ima_algo, tlv,
				include_ima_digests, include_lsm_label,
				only_executables, include_path, set_ima_xattr,
				set_evm_xattr, alt_root);
	else
		ret = gen_rpm_digest_list(hdr, dirfd, filename, head_out);
	if (ret < 0 && ret != -ENODATA)
		printf("Cannot generate %s digest list\n", filename);
out_fd:
	Fclose(fd);
out_ts:
	rpmtsFree(ts);
	return ret;
}

int pkg_generator(int dirfd, int pos, struct list_head *head_in,
		  struct list_head *head_out, enum compact_types type,
		  u16 modifiers, enum hash_algo algo, enum hash_algo ima_algo,
		  bool tlv, char *alt_root)
{
	struct path_struct *cur;
	int include_ima_digests = 0, include_lsm_label = 0, set_evm_xattr = 0;
	int only_executables = 0, include_path = 0, set_ima_xattr = 0;
	char *output_format = FORMAT;
	char *package = NULL;
	FTS *fts;
	FTSENT *ftsent;
	char *paths[2] = { NULL, NULL };
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	int ret = 0;

	if (list_empty(head_in)) {
		printf("Input path not specified\n");
		return -EINVAL;
	}

	ret = parse_options(head_in, tlv, &include_ima_digests,
			    &include_lsm_label, &only_executables,
			    &include_path, &output_format, &package,
			    &set_ima_xattr, &set_evm_xattr);
	if (ret < 0)
		return ret;

	if (!strncmp(output_format, "compact", 7)) {
		if (include_lsm_label) {
			ret = selinux_init_setup();
			if (ret)
				return ret;
		}

		if (!strcmp(output_format, "compact_tlv"))
			tlv = true;
	}

	list_for_each_entry(cur, head_in, list) {
		if (cur->path[0] != 'I')
			continue;

		paths[0] = &cur->path[2];

		fts = fts_open(paths, fts_flags, NULL);
		if (!fts)
			return -EACCES;

		while ((ftsent = fts_read(fts)) != NULL) {
			switch (ftsent->fts_info) {
			case FTS_F:
				ret = _pkg_generator(dirfd, pos,
					ftsent->fts_path, head_in, head_out,
					type, modifiers, algo, ima_algo, tlv,
					output_format, include_ima_digests,
					include_lsm_label, only_executables,
					include_path, set_ima_xattr,
					set_evm_xattr, alt_root);
				if (ret < 0 && ret != -ENOENT &&
				    ret != -ENODATA)
					goto out_fts_close;

				if (!ret && pos >= 0)
					pos++;
				break;
			default:
				break;
			}
		}

		fts_close(fts);
		fts = NULL;
	}
out_fts_close:
	if (fts)
		fts_close(fts);

	if (ret == -ENOENT || ret == -ENODATA)
		ret = 0;

	if (!strncmp(output_format, "compact", 7) && include_lsm_label)
		selinux_end_setup();

	return ret;
}
