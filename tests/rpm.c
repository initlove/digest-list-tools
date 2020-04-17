/*
 * Copyright (C) 2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: rpm.c
 *      RPM-specific tests.
 */

#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>

#include "lib.h"
#include "compact_list.h"

#define RPM_HEADER "tests/1-digestlist-rpm-libxslt-1.1.29-4.fc27-x86_64"
#define NEW_COMPACT_LIST "test_compact_list"


LIST_HEAD(ima_digest_head);

static int get_digests(int dirfd)
{
	Header hdr;
	rpmts ts = NULL;
	FD_t rpmfd;
	rpmVSFlags vsflags = 0;
	rpmtd filedigests, filemodes, filesizes;
	char **digests;
	u16 *modes;
	u32 *sizes;
	int ret, fd, i;
	struct ima_digest *new;

	ts = rpmtsCreate();
	assert_non_null(ts);

	vsflags |= _RPMVSF_NODIGESTS;
	vsflags |= _RPMVSF_NOSIGNATURES;
	rpmtsSetVSFlags(ts, vsflags);

	fd = openat(dirfd, RPM_HEADER, O_RDONLY);
	assert_return_code(fd, 0);

	rpmfd = fdDup(fd);
	assert_non_null(rpmfd);

	ret = rpmReadHeader(ts, rpmfd, &hdr, NULL);
	assert_return_code(ret, RPMRC_OK);

	filedigests = rpmtdNew();
	filemodes = rpmtdNew();
	filesizes = rpmtdNew();

	headerGet(hdr, RPMTAG_FILEDIGESTS, filedigests, 0);
	headerGet(hdr, RPMTAG_FILEMODES, filemodes, 0);
	headerGet(hdr, RPMTAG_FILESIZES, filesizes, 0);

	digests = filedigests->data;
	modes = filemodes->data;
	sizes = filesizes->data;

	for (i = 0; i < filedigests->count; i++) {
		if (!strlen(digests[i]))
			continue;

		new = calloc(1, sizeof(*new) + SHA512_DIGEST_SIZE);
		assert_non_null(new);

		new->type = COMPACT_FILE;
		new->modifiers = (1 << COMPACT_MOD_IMMUTABLE);

		if (!sizes[i])
			new->modifiers = 0;

		if (new->modifiers) {
			if (!(modes[i] & (S_IXUGO | S_ISUID | S_ISVTX)) &&
			    (modes[i] & S_IWUGO))
				new->modifiers = 0;
		}

		ret = hex2bin(new->digest, digests[i], strlen(digests[i]) / 2);
		assert_return_code(ret, 0);

		list_add_tail(&new->list, &ima_digest_head);
	}

	rpmtdFree(filesizes);
	rpmtdFree(filemodes);
	rpmtdFree(filedigests);
	headerFree(hdr);
	rpmtsFree(ts);

	Fclose(rpmfd);
	close(fd);

	return ret;
}

static int test_rpm_func(u8 *digest, enum hash_algo algo,
                         enum compact_types type, u16 modifiers)
{
	struct ima_digest *digest_struct;

	assert_false(list_empty(&ima_digest_head));

	digest_struct = list_first_entry(&ima_digest_head, struct ima_digest,
					 list);

	assert_int_equal(type, digest_struct->type);
	assert_int_equal(modifiers, digest_struct->modifiers);
	assert_memory_equal(digest, digest_struct->digest,
			    hash_digest_size[algo]);

	list_del(&digest_struct->list);
	free(digest_struct);
	return 0;
}

static void test_rpm_parser(void **state)
{
	const char rpm_str[] = "rpm";
	const char parser_str[] = "parser";
	LIST_HEAD(list_head);
	LIST_HEAD(lib_head);
	struct lib *lib;
	void *buf;
	loff_t size;
	int ret, dirfd, fd_compact_list;

	dirfd = open(".", O_RDONLY | O_DIRECTORY);
	assert_return_code(dirfd, 0);

	ret = get_digests(dirfd);
	assert_return_code(ret, 0);

	/* parse RPM header and write converted list to disk */
	lib = lookup_lib(&lib_head, parser_str, rpm_str, sizeof(rpm_str) - 1);
	assert_non_null(lib);

	fd_compact_list = openat(dirfd, NEW_COMPACT_LIST, O_WRONLY | O_CREAT,
				 0600);
	assert_return_code(fd_compact_list, 0);

	ret = read_file_from_path(dirfd, RPM_HEADER, &buf, &size);
	assert_return_code(ret, 0);

	ret = ((parser_func)lib->func)(fd_compact_list, &list_head, size, buf);
	assert_return_code(ret, 0);

	munmap(buf, size);

	ret = compact_list_flush_all(fd_compact_list, &list_head);
	assert_return_code(ret, 0);
	assert_true(list_empty(&list_head));

	close(fd_compact_list);
	free_libs(&lib_head);

	/* parse converted list */
	ret = read_file_from_path(dirfd, NEW_COMPACT_LIST, &buf, &size);
	assert_return_code(ret, 0);

	ret = ima_parse_compact_list(size, buf, test_rpm_func);
	assert_return_code(ret, 0);

	munmap(buf, size);
	close(dirfd);
}

void cleanup(void **state)
{
	int dirfd;

	dirfd = open(".", O_RDONLY | O_DIRECTORY);
	assert_return_code(dirfd, 0);

	unlinkat(dirfd, NEW_COMPACT_LIST, 0);
	close(dirfd);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_rpm_parser),
		cmocka_unit_test(cleanup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
