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
 * File: compact_tlv.c
 *      Compact TLV-specific tests.
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "lib.h"
#include "xattr.h"
#include "crypto.h"
#include "compact_list.h"

#define FILE_DIGEST \
	"5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"
#define NEW_FILE "new_file"
#define NEW_COMPACT_LIST "test_compact_list"

static int test_digest_func(u8 *digest, enum hash_algo algo,
			    enum compact_types type, u16 modifiers)
{
	u8 ref_digest[SHA512_DIGEST_SIZE];
	enum hash_algo expected_algo = HASH_ALGO_SHA256;
	int ret;

	assert_int_equal(modifiers, (1 << COMPACT_MOD_IMMUTABLE));
	assert_int_equal(algo, expected_algo);

	ret = hex2bin(ref_digest, FILE_DIGEST, hash_digest_size[algo]);
	assert_return_code(ret, 0);

	assert_memory_equal(digest, ref_digest, hash_digest_size[algo]);
	return 0;
}

static int test_metadata_digest_func(u8 *digest, enum hash_algo algo,
				     enum compact_types type, u16 modifiers)
{
	u8 calculated_digest[SHA512_DIGEST_SIZE];
	u8 *inode_metadata_buf;
	int selinux_label_len, ima_xattr_len, buf_len;
	enum hash_algo expected_algo = HASH_ALGO_SHA256;
	struct stat st;
	int ret;

	struct h_misc {
		unsigned long ino;
		u32 generation;
		uid_t uid;
		gid_t gid;
		mode_t mode;
	} inode_metadata = { 0 };

	assert_int_equal(modifiers, (1 << COMPACT_MOD_IMMUTABLE));
	assert_int_equal(algo, expected_algo);

	ret = stat(NEW_FILE, &st);
	assert_return_code(ret, 0);

	selinux_label_len = getxattr(NEW_FILE, XATTR_NAME_SELINUX, NULL, 0);
	if (selinux_label_len < 0)
		selinux_label_len = 0;

	inode_metadata.uid = st.st_uid;
	inode_metadata.gid = st.st_gid;
	inode_metadata.mode = st.st_mode;

	buf_len = selinux_label_len + 2 + hash_digest_size[algo] + \
		  sizeof(inode_metadata);

	inode_metadata_buf = malloc(buf_len);
	assert_non_null(inode_metadata_buf);

	if (selinux_label_len) {
		ret = getxattr(NEW_FILE, XATTR_NAME_SELINUX, inode_metadata_buf,
			buf_len);
		assert_return_code(ret, 0);
	}

	ret = calc_file_digest(calculated_digest, -1, NEW_FILE, algo);
	assert_return_code(ret, 0);

	ret = gen_write_ima_xattr(inode_metadata_buf + selinux_label_len,
				  &ima_xattr_len, NEW_FILE, algo,
				  calculated_digest, true, false);
	assert_return_code(ret, 0);

	memcpy(inode_metadata_buf + selinux_label_len + ima_xattr_len,
	       &inode_metadata, sizeof(inode_metadata));

	ret = calc_digest(calculated_digest, inode_metadata_buf, buf_len, algo);
	assert_return_code(ret, 0);

	assert_memory_equal(calculated_digest, digest, hash_digest_size[algo]);
	free(inode_metadata_buf);
	return 0;
}

static void test_compact_tlv_parser(void **state)
{
	const char compact_str[] = "compact-test";
	const char compact_tlv_str[] = "compact_tlv-test";
	const char generator_str[] = "generator";
	const char parser_str[] = "parser";
	char path[PATH_MAX];
	LIST_HEAD(generator_lib_head);
	LIST_HEAD(parser_lib_head);
	LIST_HEAD(head_in);
	LIST_HEAD(head_out);
	LIST_HEAD(list_head);
	struct lib *generator_lib, *parser_lib;
	struct path_struct *item;
	void *gen_list_buf, *buf;
	loff_t gen_list_size, size;
	int ret, dirfd, fd, fd_compact_list;

	dirfd = open(".", O_RDONLY | O_DIRECTORY);
	assert_return_code(dirfd, 0);

	snprintf(path, sizeof(path), "I:%s", NEW_FILE);
	fd = open(&path[2], O_WRONLY | O_CREAT, 0644);
	assert_return_code(fd, 0);

	ret = write(fd, "0", 1);
	assert_return_code(fd, 0);

	close(fd);

	/* generate a TLV compact list */
	generator_lib = lookup_lib(&generator_lib_head, generator_str,
				   compact_str, sizeof(compact_str) - 1);
	assert_non_null(generator_lib);

	ret = add_path_struct(path, NULL, &head_in);
	assert_return_code(ret, 0);

	ret = ((generator_func)generator_lib->func)(dirfd, 0, &head_in,
						&head_out, COMPACT_FILE,
						(1 << COMPACT_MOD_IMMUTABLE),
						HASH_ALGO_SHA256,
						HASH_ALGO_SHA256, true, NULL);
	assert_return_code(ret, 0);
	assert_false(list_empty(&head_out));

	item = list_first_entry(&head_out, struct path_struct, list);
	ret = read_file_from_path(dirfd, item->path, &gen_list_buf,
				  &gen_list_size);
	assert_return_code(ret, 0);

	unlinkat(dirfd, item->path, 0);

	/* parse the TLV compact list and write converted list to disk */
	parser_lib = lookup_lib(&parser_lib_head, parser_str, compact_tlv_str,
				sizeof(compact_tlv_str) - 1);
	assert_non_null(parser_lib);

	fd_compact_list = openat(dirfd, NEW_COMPACT_LIST,
				 O_WRONLY | O_CREAT | O_TRUNC, 0644);
	assert_return_code(fd_compact_list, 0);

	ret = ((parser_func)parser_lib->func)(fd_compact_list, &list_head,
					      gen_list_size, gen_list_buf,
					      PARSER_OP_ADD_DIGEST, NULL);
	assert_return_code(ret, 0);

	ret = compact_list_flush_all(fd_compact_list, &list_head);
	assert_return_code(ret, 0);

	close(fd_compact_list);
	free_path_structs(&head_in);
	free_path_structs(&head_out);
	free_libs(&generator_lib_head);
	free_libs(&parser_lib_head);

	/* parse converted list */
	ret = read_file_from_path(dirfd, NEW_COMPACT_LIST, &buf, &size);
	assert_return_code(ret, 0);

	ret = ima_parse_compact_list(size, buf, test_digest_func, NULL);
	assert_return_code(ret, 0);
	munmap(buf, size);

	fd_compact_list = openat(dirfd, NEW_COMPACT_LIST,
				 O_WRONLY | O_CREAT | O_TRUNC, 0644);
	assert_return_code(fd_compact_list, 0);

	ret = ((parser_func)parser_lib->func)(fd_compact_list, &list_head,
					      gen_list_size, gen_list_buf,
					      PARSER_OP_ADD_META_DIGEST,
					      NULL);
	assert_return_code(ret, 0);

	ret = compact_list_flush_all(fd_compact_list, &list_head);
	assert_return_code(ret, 0);
	close(fd_compact_list);

	/* parse converted list */
	ret = read_file_from_path(dirfd, NEW_COMPACT_LIST, &buf, &size);
	assert_return_code(ret, 0);

	ret = ima_parse_compact_list(size, buf, test_metadata_digest_func,
				     NULL);
	assert_return_code(ret, 0);
	munmap(buf, size);
	munmap(gen_list_buf, gen_list_size);
}

void cleanup(void **state)
{
	int dirfd;

	dirfd = open(".", O_RDONLY | O_DIRECTORY);
	assert_return_code(dirfd, 0);

	unlinkat(dirfd, NEW_FILE, 0);
	unlinkat(dirfd, NEW_COMPACT_LIST, 0);
	close(dirfd);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_compact_tlv_parser),
		cmocka_unit_test(cleanup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
