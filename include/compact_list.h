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
 * File: compact_list.h
 *      Header of compact_list.c.
 */

#ifndef _COMPACT_LIST_H
#define _COMPACT_LIST_H

#include "lib.h"

#define COMPACT_LIST_SIZE_MAX 64 * 1024 * 1024 - 1

extern char *compact_types_str[COMPACT__LAST];
extern char *compact_modifiers_str[COMPACT_MOD__LAST];

struct list_struct {
	struct list_head list;
	struct compact_list_hdr *hdr;
};

struct list_struct *compact_list_init(struct list_head *list_head,
				      enum compact_types type, u16 modifiers,
				      enum hash_algo algo);
int compact_list_add_digest(int fd, struct list_struct *list, u8 *digest);
int compact_list_upload(int fd, struct list_struct *list);
int compact_list_flush_all(int fd, struct list_head *list_head);

typedef int (*generator_func)(int dirfd, int pos, struct list_head *head_in,
			      struct list_head *head_out,
			      enum compact_types type, u16 modifiers,
			      enum hash_algo algo);
typedef int (*parser_func)(int imafd, struct list_head *head,
			   loff_t size, void *buf);

int gen_filename_prefix(char *filename, int filename_len, int pos,
			const char *format, enum compact_types type);

typedef int (*filter_lists)(const struct dirent *file);

int filter_parser_list_symlink(const struct dirent *file);
extern filter_lists filter[COMPACT__LAST];
int get_digest_lists(int dirfd, enum compact_types type,
		     struct list_head *head);
int compare_lists(const struct dirent **e1, const struct dirent **e2);

#endif /*_COMPACT_LIST_H*/
