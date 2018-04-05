/*
 * Copyright (C) 2017 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: securityfs.c
 *      Upload parsed digest lists to IMA.
 */

#include "securityfs.h"

#define NUM_PAGE_DIGESTS 2

static int fs_mounted;
int ima_fd = -1;
int digests;
int sent_digests;
int digest_lists;

struct page_digest {
	u8 data[4095];
	int datalen;
	int reset;
};

struct page_digest *pages;

static void ima_check_init_page_digest(void)
{
	int i;

	for (i = 0; i < NUM_PAGE_DIGESTS; i++) {
		if (pages[i].reset) {
			memset(&pages[i], 0, sizeof(*pages));
			pages[i].datalen = sizeof(struct compact_list_hdr);
		}
	}
}

static void ima_reset_page_digest(int index)
{
	int i;

	for (i = 0; i < NUM_PAGE_DIGESTS; i++)
		if (index == -1 || i == index)
			pages[i].reset = 1;
}

static int ima_add_digest_data(struct page_digest *page, u8 *digest,
			       u16 digest_algo)
{
	int remaining;

	remaining = sizeof(page->data) - page->datalen;

	if (remaining < hash_digest_size[digest_algo])
		return 1;

	memcpy(page->data + page->datalen, digest,
	       hash_digest_size[digest_algo]);
	page->datalen += hash_digest_size[digest_algo];
	return 0;
}

int ima_add_digest_data_entry(u8 *digest, u16 digest_algo, u8 flags, u16 type,
			      enum actions action)
{
	int index, buffer_full, ret;
	struct compact_list_hdr *hdr;

	if (action == ACTION_ADD || action == ACTION_RESET) {
		if (action == ACTION_ADD && (type == DATA_TYPE_REG_FILE ||
		    type == DATA_TYPE_DIGEST_LIST))
			digests++;
		if (type == DATA_TYPE_DIGEST_LIST)
			digest_lists++;
	}

	if (ima_fd < 0)
		return 0;

retry:
	buffer_full = 0;

	if (action == ACTION_RESET)
		ima_reset_page_digest(-1);

	ima_check_init_page_digest();

	if (action != ACTION_ADD && action != ACTION_FLUSH)
		return 0;

	index = (flags & DIGEST_FLAG_IMMUTABLE) ? 0 : 1;

	hdr = (void *)pages[index].data;
	if (action == ACTION_ADD) {
		if (hdr->count == 0) {
			hdr->algo = digest_algo;
			hdr->entry_id = COMPACT_DIGEST;
			if (type == DATA_TYPE_DIGEST_LIST)
				hdr->entry_id = COMPACT_DIGEST_LIST;
			else if (flags == 0)
				hdr->entry_id = COMPACT_DIGEST_MUTABLE;
		}

		buffer_full = ima_add_digest_data(&pages[index], digest,
						  digest_algo);
	}

	if (action == ACTION_FLUSH || buffer_full) {
		u32 digests_to_send = hdr->count;

		if (ima_canonical_fmt) {
			hdr->entry_id = cpu_to_le16(hdr->entry_id);
			hdr->algo = cpu_to_le16(digest_algo);
			hdr->count = cpu_to_le32(hdr->count);
			hdr->datalen = cpu_to_le32(hdr->datalen);
		}

		ret = write_check(ima_fd, pages[index].data,
				  pages[index].datalen);
		if (ret < 0)
			return ret;

		sent_digests += digests_to_send;
		ima_reset_page_digest(index);

		if (buffer_full)
			goto retry;

		return 0;
	}

	hdr->count++;
	hdr->datalen += hash_digest_size[digest_algo];
	return 0;
}

int ima_flush_digest_list_buffer(void)
{
	int ret;

	ret = ima_add_digest_data_entry(NULL, 0, 0, 0, ACTION_FLUSH);
	if (ret == 0)
		ret = ima_add_digest_data_entry(NULL, 0, DIGEST_FLAG_IMMUTABLE,
						0, ACTION_FLUSH);

	return ret;
}

int ima_init_upload(enum securityfs_files id)
{
	char *path = (id == DIGEST_LIST_METADATA) ?
		     IMA_DIGEST_LIST_METADATA_PATH : IMA_DIGEST_LIST_DATA_PATH;
	struct stat st;
	int ret;

	ret = stat(IMA_SECURITYFS_PATH, &st);
	if (ret < 0) {
		ret = mount(SYSFS_PATH, SYSFS_PATH, "sysfs", MOUNT_FLAGS, NULL);
		if (ret < 0)
			return ret;

		ret = mount(SECURITYFS_PATH, SECURITYFS_PATH, "securityfs",
			MOUNT_FLAGS, NULL);
		if (ret < 0)
			return ret;

		fs_mounted = 1;
	}

	ima_fd = open(path, O_WRONLY);
	if (ima_fd < 0)
		return -EACCES;

	pages = calloc(NUM_PAGE_DIGESTS, sizeof(*pages));
	if (pages == NULL)
		return -ENOMEM;

	return 0;
}

void ima_end_upload(void)
{
	free(pages);

	if (ima_fd != -1)
		close(ima_fd);

	if (fs_mounted) {
		umount(SECURITYFS_PATH);
		umount(SYSFS_PATH);
	}
}

int ima_upload_metadata(void *buf, loff_t size)
{
	return write_check(ima_fd, buf, size);
}
