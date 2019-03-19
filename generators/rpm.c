/*
 * Copyright (C) 2017-2019 Huawei Technologies Duesseldorf GmbH
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

#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>

#include "compact_list.h"
#include "xattr.h"

#define FORMAT "rpm"


const unsigned char rpm_header_magic[8] = {
	0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
};

static void gen_filename(Header rpm, int pos, enum compact_types type,
			 char *filename, int filename_len)
{
	rpmtd name = rpmtdNew(), version = rpmtdNew();
	rpmtd release = rpmtdNew(), arch = rpmtdNew();
	int prefix_len;

	headerGet(rpm, RPMTAG_NAME, name, 0);
	headerGet(rpm, RPMTAG_VERSION, version, 0);
	headerGet(rpm, RPMTAG_RELEASE, release, 0);
	headerGet(rpm, RPMTAG_ARCH, arch, 0);

	prefix_len = gen_filename_prefix(filename, filename_len, pos, FORMAT,
					 type);

	snprintf(filename + prefix_len, filename_len - prefix_len,
		 "%s-%s-%s-%s", rpmtdGetString(name), rpmtdGetString(version),
		 rpmtdGetString(release), rpmtdGetString(arch));

	rpmtdFree(name);
	rpmtdFree(version);
	rpmtdFree(release);
	rpmtdFree(arch);
}

static int gen_rpm_digest_list(Header rpm, int dirfd, char *filename,
			       struct list_head *head_out)
{
	rpmtd immutable;
	ssize_t ret;
	int fd;

	fd = openat(dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
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
		ret = add_path_struct(filename, head_out);

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

		if (!strcmp(cur_path_ptr, filename_ptr))
			return 1;
	}

	return 0;
}

int db_generator(int dirfd, int pos, struct list_head *head_in,
		 struct list_head *head_out, enum compact_types type,
		 u16 modifiers, enum hash_algo algo)
{
	char filename[NAME_MAX + 1];
	rpmts ts = NULL;
	Header hdr;
	rpmdbMatchIterator mi;
	LIST_HEAD(digest_list_head);
	int ret;

	ret = get_digest_lists(dirfd, type, &digest_list_head);
	if (ret < 0)
		goto out;

	ts = rpmtsCreate();
	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		goto out;
	}

	mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
	while ((hdr = rpmdbNextIterator(mi)) != NULL) {
		gen_filename(hdr, pos, type, filename, sizeof(filename));

		if (strstr(filename, "gpg-pubkey") != NULL)
			continue;

		if (find_file(&digest_list_head, filename))
			continue;

		ret = gen_rpm_digest_list(hdr, dirfd, filename, head_out);
		if (ret < 0) {
			printf("Cannot generate %s digest list\n", filename);
			break;
		}

		pos++;
	}

	if (hdr)
		headerFree(hdr);

	rpmdbFreeIterator(mi);
	rpmFreeRpmrc();
	rpmtsFree(ts);
out:
	free_path_structs(&digest_list_head);
	return ret;
}

static int _pkg_generator(int dirfd, int pos, char *path,
			  struct list_head *head_out, enum compact_types type,
			  enum hash_algo algo)
{
	char filename[NAME_MAX + 1];
	Header hdr;
	rpmts ts = NULL;
	FD_t fd;
	int ret;
	rpmVSFlags vsflags = 0;

	ts = rpmtsCreate();

	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		ret = -ENOENT;
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
		goto out_fd;
	}

	ret = rpmReadPackageFile(ts, fd, "rpm", &hdr);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Could not read package file %s\n", path);
		goto out_fd;
	}

	gen_filename(hdr, pos, type, filename, sizeof(filename));

	ret = gen_rpm_digest_list(hdr, dirfd, filename, head_out);
	if (ret < 0)
		printf("Cannot generate %s digest list\n", filename);
out_fd:
	Fclose(fd);
out_ts:
	rpmtsFree(ts);
	return ret;
}

int pkg_generator(int dirfd, int pos, struct list_head *head_in,
		  struct list_head *head_out, enum compact_types type,
		  u16 modifiers, enum hash_algo algo)
{
	struct path_struct *cur;
	int ret = 0;

	if (list_empty(head_in)) {
		printf("Input path not specified\n");
		return -EINVAL;
	}

	list_for_each_entry(cur, head_in, list) {
		ret = _pkg_generator(dirfd, pos, cur->path, head_out, type,
				     algo);
		if (ret < 0)
			return ret;
	}

	return ret;
}
