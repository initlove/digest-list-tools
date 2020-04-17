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
 * File: ima.c
 *      Parses IMA measurement list (ima-ng template, ASCII).
 */

#include <errno.h>

#include "compact_list.h"

int ima_ng_parser(int fd, struct list_head *head, loff_t size, void *buf)
{
	char *buf_startp = buf, *buf_endp, *modifier_ptr;
	char *linep, *algo_endp, *digest_startp, *digest_endp;
	u8 digest[SHA512_DIGEST_SIZE];
	enum hash_algo algo;
	u16 modifiers = 0;
	struct list_struct *list[HASH_ALGO__LAST] = { NULL };
	int ret = 0, i, digest_len;

	while ((buf_endp = strchr(buf_startp, '\n'))) {
		if (buf_startp == buf) {
			modifier_ptr = buf_startp;
			while ((modifier_ptr = strsep(&buf_startp, " \n"))) {
				for (i = 0; i < COMPACT_MOD__LAST; i++) {
					if (!strcmp(modifier_ptr,
						    compact_modifiers_str[i])) {
						modifiers |= (1 << i);
						break;
					}
				}

				if (buf_startp > buf_endp)
					break;
			}
			buf_startp = buf_endp + 1;
			continue;
		}

		digest_endp = digest_startp = buf_startp;

		for (i = 0, linep = buf_startp; i < 5 && linep;
		     i++, linep = strchr(linep + 1, ' ')) {
			if (i == 3)
				digest_startp = linep + 1;
			else if (i == 4)
				digest_endp = linep;
		}

		for (algo = 0; algo < HASH_ALGO__LAST; algo++) {
			algo_endp = strchr(digest_startp, ':');
			if (!algo_endp) {
				printf("Malformed line\n");
				return -EINVAL;
			}

			if (!strncmp(digest_startp, hash_algo_name[algo],
				     algo_endp - digest_startp))
				break;
		}

		if (algo == HASH_ALGO__LAST) {
			printf("Unknown algorithm\n");
			return -EINVAL;
		}

		if (!list[algo]) {
			list[algo] = compact_list_init(head, COMPACT_FILE,
						       modifiers, algo);
			if (!list[algo])
				return -ENOMEM;
		}

		digest_len = hash_digest_size[algo];

		if (digest_endp - algo_endp - 1 != digest_len * 2) {
			printf("Malformed line\n");
			return -EINVAL;
		}

		ret = hex2bin(digest, algo_endp + 1, digest_len);
		if (ret < 0)
			return ret;

		ret = compact_list_add_digest(fd, list[algo], digest);
		if (ret < 0)
			return ret;

		buf_startp = buf_endp + 1;
	}

	return 0;
}
