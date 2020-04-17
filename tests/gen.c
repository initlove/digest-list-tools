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
 * File: gen.c
 *      gen_digest_lists tests.
 */

#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lib.h"
#include "compact_list.h"


static void test_gen(void **state)
{
	struct stat st;
	int ret;

	if (fork() == 0) {
		execlp("src/gen_digest_lists", "gen_digest_lists",
		       "-t", "parser", "-o", "append", "-f", "compact",
		       "-i", "I:src/upload_digest_lists", "-d", "test", NULL);
	}

	wait(NULL);

	ret = stat("test/0-parser_list-compact-upload_digest_lists", &st);
	assert_return_code(ret, 0);

	if (fork() == 0) {
		execlp("src/gen_digest_lists", "gen_digest_lists",
		       "-t", "parser", "-o", "add", "-f", "compact", "-p", "0",
		       "-i", "I:src/upload_digest_lists", "-d", "test", NULL);
	}

	wait(NULL);

	ret = stat("test/1-parser_list-compact-upload_digest_lists", &st);
	assert_return_code(ret, 0);

	if (fork() == 0) {
		execlp("src/gen_digest_lists", "gen_digest_lists",
		       "-t", "parser", "-o", "remove", "-p", "0", "-d", "test",
		       NULL);
	}

	wait(NULL);

	if (fork() == 0) {
		execlp("src/gen_digest_lists", "gen_digest_lists",
		       "-t", "parser", "-o", "remove", "-p", "0", "-d", "test",
		       NULL);
	}

	wait(NULL);
}

void test_gen_init(void **state)
{
	mkdir("test", 0755);
}

void test_gen_cleanup(void **state)
{
	struct stat st;
	int ret;

	rmdir("test");

	ret = stat("test", &st);
	assert_int_equal(ret, -1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_gen_init),
		cmocka_unit_test(test_gen),
		cmocka_unit_test(test_gen_cleanup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
