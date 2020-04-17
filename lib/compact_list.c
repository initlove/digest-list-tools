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
 * File: compact_list.c
 *      Writes compact digest lists.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <sys/mman.h>

#include "compact_list.h"
#include "lib.h"


char *compact_types_str[COMPACT__LAST] = {
	[COMPACT_KEY] = "key",
	[COMPACT_PARSER] = "parser",
	[COMPACT_FILE] = "file",
};

char *compact_modifiers_str[COMPACT_MOD__LAST] = {
	[COMPACT_MOD_IMMUTABLE] = "immutable",
};

struct list_struct *compact_list_init(struct list_head *head,
				      enum compact_types type, u16 modifiers,
				      enum hash_algo algo)
{
	struct list_struct *list;

	list_for_each_entry(list, head, list) {
		if (list->hdr->type == type &&
		    list->hdr->modifiers == modifiers &&
		    list->hdr->algo == algo)
			return list;
	}

	list = malloc(sizeof(*list));
	if (!list)
		return list;

	list->hdr = mmap(NULL, COMPACT_LIST_SIZE_MAX, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (list->hdr == MAP_FAILED) {
		printf("Cannot allocate buffer\n");
		return NULL;
	}

	list->hdr->version = 1;
	list->hdr->type = type;
	list->hdr->modifiers = modifiers;
	list->hdr->algo = algo;
	list->hdr->count = 0;
	list->hdr->datalen = 0;
	list_add_tail(&list->list, head);

	return list;
}

int compact_list_add_digest(int fd, struct list_struct *list, u8 *digest)
{
	struct compact_list_hdr *hdr = list->hdr;
	int digest_len = hash_digest_size[hdr->algo];
	void *ptr;

	ptr = (void *)hdr + sizeof(*hdr) + hdr->datalen;

	memcpy(ptr, digest, digest_len);
	hdr->datalen += digest_len;
	hdr->count++;

	if (hdr->datalen + digest_len < COMPACT_LIST_SIZE_MAX)
		return 0;

	return compact_list_upload(fd, list);
}

int compact_list_upload(int fd, struct list_struct *list)
{
	struct compact_list_hdr *hdr = list->hdr;
	struct compact_list_hdr h = { .version = hdr->version,
				      .type = hdr->type,
				      .modifiers = hdr->modifiers,
				      .algo = hdr->algo,
				      .count = 0,
				      .datalen = 0 };
	u32 datalen;
	int ret;

	if (fd < 0)
		return 0;

	hdr = list->hdr;
	datalen = hdr->datalen;

	if (!datalen)
		return 0;

	if (ima_canonical_fmt) {
		hdr->type = cpu_to_le16(hdr->type);
		hdr->modifiers = cpu_to_le16(hdr->modifiers);
		hdr->algo = cpu_to_le16(hdr->algo);
		hdr->count = cpu_to_le32(hdr->count);
		hdr->datalen = cpu_to_le32(hdr->datalen);
	}

	ret = write_check(fd, (void *)hdr, sizeof(*hdr) + datalen);
	memcpy(hdr, &h, sizeof(h));
	return ret;
}

int compact_list_flush_all(int fd, struct list_head *head)
{
	struct list_struct *p, *q;
	int ret = 0;

	if (fd < 0)
		return 0;

	list_for_each_entry_safe(p, q, head, list) {
		if (!ret)
			ret = compact_list_upload(fd, p);

		munmap(p->hdr, COMPACT_LIST_SIZE_MAX);
		list_del(&p->list);
		free(p);
	}

	return ret;
}

int gen_filename_prefix(char *filename, int filename_len, int pos,
			const char *format, enum compact_types type)
{
	return snprintf(filename, filename_len, "%d-%s_list-%s-", pos,
			compact_types_str[type], format);
}

static int filter_lists_common(const struct dirent *file,
			       enum compact_types type)
{
	const char *filename = file->d_name;
	char id_str[NAME_MAX + 1];
	unsigned long pos;
	char *ptr;

	pos = strtoul(filename, &ptr, 10);
	if (pos < 0)
		return 0;

	snprintf(id_str, sizeof(id_str), "-%s_list-", compact_types_str[type]);

	if (strncmp(ptr, id_str, strlen(id_str)))
		return 0;

	if (!strncmp(filename + strlen(filename) - 4, ".sig", 4))
		return 0;

	return 1;
}

int filter_key_lists(const struct dirent *file)
{
	return filter_lists_common(file, COMPACT_KEY);
}

int filter_parser_lists(const struct dirent *file)
{
	return filter_lists_common(file, COMPACT_PARSER);
}

int filter_parser_list_symlink(const struct dirent *file)
{
	if (file->d_type == DT_LNK &&
	    !strncmp(file->d_name, "compact-", 8))
		return 1;

	return 0;
}

int filter_file_lists(const struct dirent *file)
{
	return filter_lists_common(file, COMPACT_FILE);
}

filter_lists filter[COMPACT__LAST] = {
	[COMPACT_KEY] = filter_key_lists,
	[COMPACT_PARSER] = filter_parser_lists,
	[COMPACT_FILE] = filter_file_lists,
};

int get_digest_lists(int dirfd, enum compact_types type, struct list_head *head)
{
	struct dirent **digest_lists;
	int ret = 0, i, n;

	n = scandirat(dirfd, ".", &digest_lists, filter[type], compare_lists);
	if (n == -1) {
		printf("Unable to access digest lists\n");
		return -EACCES;
	}

	for (i = 0; i < n; i++) {
		if (!ret)
			ret = add_path_struct(digest_lists[i]->d_name, head);

		free(digest_lists[i]);
	}

	free(digest_lists);
	return ret;
}

int compare_lists(const struct dirent **e1, const struct dirent **e2)
{
	unsigned long v1 = strtoul((*e1)->d_name, NULL, 10);
	unsigned long v2 = strtoul((*e2)->d_name, NULL, 10);

	return v1 - v2;
}
