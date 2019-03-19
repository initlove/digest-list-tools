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
 * File: lib.c
 *      Library-specific tests.
 */

#include "lib.h"
#include "compact_list.h"


static void test_lib_lookup(void **state)
{
	LIST_HEAD(lib_head);
	struct lib *first_lib, *second_lib, *third_lib;
	const char parser_str[] = "parser";
	const char rpm_str[] = "rpm";
	const char rpm_db_str[] = "rpm+db-test";
	const char ima_ng_str[] = "ima+ima_ng-test";

	first_lib = lookup_lib(&lib_head, parser_str, rpm_str,
			       sizeof(rpm_str) - 1);
	assert_non_null(first_lib);
	assert_memory_equal(first_lib->format, rpm_str, sizeof(rpm_str) - 1);

	second_lib = lookup_lib(&lib_head, parser_str, rpm_db_str,
				sizeof(rpm_db_str) - 1);
	assert_non_null(second_lib);

	assert_ptr_equal(first_lib, second_lib);

	third_lib = lookup_lib(&lib_head, parser_str, ima_ng_str,
			       sizeof(ima_ng_str) - 1);
	assert_non_null(third_lib);

	free_libs(&lib_head);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_lib_lookup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
