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
 * File: ima.c
 *      IMA-specific tests.
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "lib.h"
#include "compact_list.h"

#define IMA_NG_PCR "10"
#define IMA_NG_TEMPLATE_DIGEST "653fc8402b3c58926e3b5b0e9ff40d9cf5d906cb"
#define IMA_NG_TEMPLATE_NAME "ima-ng"
#define IMA_NG_FILE_DIGEST "sha256:a0efbbc00dd27516569793a7360877042c35cfd5c45\
17c36665f45f160c14e20"
#define IMA_NG_FILE_PATH "/usr/lib/systemd/systemd"

#define IMA_NG_ENTRY IMA_NG_PCR " " IMA_NG_TEMPLATE_DIGEST " " \
                    IMA_NG_TEMPLATE_NAME " " IMA_NG_FILE_DIGEST " " \
                    IMA_NG_FILE_PATH "\n"

#define IMA_MEASUREMENTS "ima_measurements.txt"
#define NEW_COMPACT_LIST "test_compact_list"


static int test_ima_func(u8 *digest, enum hash_algo algo,
                         enum compact_types type, u16 modifiers)
{
	u8 ima_digest[SHA512_DIGEST_SIZE];
	enum hash_algo expected_algo = HASH_ALGO_SHA256;
	int ret;

	assert_int_equal(modifiers, (1 << COMPACT_MOD_IMMUTABLE));
	assert_int_equal(algo, expected_algo);

	ret = hex2bin(ima_digest, IMA_NG_FILE_DIGEST + 7,
		      hash_digest_size[algo]);
	assert_return_code(ret, 0);

	assert_memory_equal(digest, ima_digest, hash_digest_size[algo]);
	return 0;
}

static void test_ima_parser(void **state)
{
	const char ima_ng_str[] = "ima+ima_ng";
	const char generator_str[] = "generator";
	const char parser_str[] = "parser";
	LIST_HEAD(generator_lib_head);
	LIST_HEAD(parser_lib_head);
	LIST_HEAD(head_in);
	LIST_HEAD(head_out);
	LIST_HEAD(list_head);
	struct lib *generator_lib, *parser_lib;
	struct path_struct *item;
	void *buf;
	loff_t size;
	int ret, dirfd, fd_ima_ng, fd_compact_list;

	dirfd = open(".", O_RDONLY | O_DIRECTORY);
	assert_return_code(dirfd, 0);

	/* write IMA measurement list */
	fd_ima_ng = open(IMA_MEASUREMENTS, O_WRONLY | O_CREAT, 0600);
	assert_return_code(fd_ima_ng , 0);

	ret = write_check(fd_ima_ng, IMA_NG_ENTRY, sizeof(IMA_NG_ENTRY) - 1);
	assert_return_code(ret, 0);

	close(fd_ima_ng);

	/* generate IMA digest list */
	generator_lib = lookup_lib(&generator_lib_head, generator_str,
				   ima_ng_str, sizeof(ima_ng_str) - 1);
	assert_non_null(generator_lib);

	ret = add_path_struct(IMA_MEASUREMENTS, &head_in);
	assert_return_code(ret, 0);

	ret = ((generator_func)generator_lib->func)(dirfd, 0, &head_in,
						&head_out, COMPACT_FILE,
						(1 << COMPACT_MOD_IMMUTABLE),
						HASH_ALGO_SHA256);
	assert_return_code(ret, 0);
	assert_false(list_empty(&head_out));

	item = list_first_entry(&head_out, struct path_struct, list);
	ret = read_file_from_path(dirfd, item->path, &buf, &size);
	assert_return_code(ret, 0);

	unlinkat(dirfd, item->path, 0);

	/* parse IMA digest list and write converted list to disk */
	parser_lib = lookup_lib(&parser_lib_head, parser_str, ima_ng_str,
				sizeof(ima_ng_str) - 1);
	assert_non_null(parser_lib);

	fd_compact_list = openat(dirfd, NEW_COMPACT_LIST,
				 O_WRONLY | O_CREAT | O_TRUNC, 0600);
	assert_return_code(fd_compact_list, 0);

	ret = ((parser_func)parser_lib->func)(fd_compact_list, &list_head,
					      size, buf);
	assert_return_code(ret, 0);

	munmap(buf, size);

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

	ret = ima_parse_compact_list(size, buf, test_ima_func);
	assert_return_code(ret, 0);
	munmap(buf, size);
}

void cleanup(void **state)
{
	int dirfd;

	dirfd = open(".", O_RDONLY | O_DIRECTORY);
	assert_return_code(dirfd, 0);

	unlinkat(dirfd, IMA_MEASUREMENTS, 0);
	unlinkat(dirfd, NEW_COMPACT_LIST, 0);
	close(dirfd);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ima_parser),
		cmocka_unit_test(cleanup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
