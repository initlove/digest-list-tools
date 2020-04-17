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
 * File: ima_list.c
 *      Library to generate an IMA measurements list.
 */

#include <sys/xattr.h>

#include "crypto.h"
#include "xattr.h"
#include "ima_list.h"

#define TCG_EVENT_NAME_LEN_MAX 255
#define DIGEST_LIST_PCR 16
#define IMA_SIG_TEMPLATE "ima-sig"
#define IMA_DIGEST_ALGO HASH_ALGO_SHA256
#define IMA_PATH "/sys/kernel/security/ima/binary_runtime_measurements"
#define BUFLEN 1024

struct template_entry {
	struct {
		uint32_t pcr;
		uint8_t digest[SHA_DIGEST_LENGTH];
		uint32_t name_len;
	} header __attribute__((packed));
	char name[TCG_EVENT_NAME_LEN_MAX + 1];
	int template_len;
	uint8_t *template;
	int template_buf_len;
};

int ima_copy_boot_aggregate(int fd)
{
	u8 buf[BUFLEN];
	size_t len;
	int ret = 0, fd_ima;

	fd_ima = open(IMA_PATH, O_RDONLY);
	if (fd_ima < 0)
		return -EACCES;

	while ((len = read(fd_ima, buf, BUFLEN))) {
		ret = write_check(fd, buf, len);
		if (ret < 0)
			goto out;
	}
out:
	close(fd_ima);
	return ret;
}

int ima_generate_entry(int dirfd, int fd, char *digest_list_dir,
		       char *digest_list_filename)
{
	struct template_entry entry;
	uint32_t *field_len, current_offset, offset = 0;
	size_t keyid_len, sig_len, algo_name_len, xattr_len;
	enum hash_algo algo;
	u8 *xattr, *keyid, *sig;
	int ret;

	entry.header.pcr = DIGEST_LIST_PCR;
	entry.header.name_len = sizeof(IMA_SIG_TEMPLATE) - 1;

	memcpy(entry.name, IMA_SIG_TEMPLATE, sizeof(IMA_SIG_TEMPLATE) - 1);

	entry.template_buf_len =
		     /* d-ng template field */
		     CRYPTO_MAX_ALG_NAME + 2 + SHA512_DIGEST_SIZE +
		     /* n-ng template field */
		     PATH_MAX +
		     /* sig template field */
		     MAX_SIGNATURE_SIZE;

	entry.template = malloc(entry.template_buf_len);
	if (!entry.template)
		return -ENOMEM;

	/* d-ng template field */
	field_len = (uint32_t *)(entry.template + offset);

	offset += sizeof(*field_len);
	current_offset = offset;

	algo_name_len = strlen(hash_algo_name[IMA_DIGEST_ALGO]);
	memcpy(entry.template + offset, hash_algo_name[IMA_DIGEST_ALGO],
	       algo_name_len);
	offset += algo_name_len;

	entry.template[offset++] = ':';
	entry.template[offset++] = '\0';

	ret = calc_file_digest(entry.template + offset, dirfd,
			      digest_list_filename, IMA_DIGEST_ALGO);
	if (ret < 0)
		goto out;

	offset += hash_digest_size[IMA_DIGEST_ALGO];
	*field_len = (offset - current_offset);

	if (ima_canonical_fmt)
		*field_len = cpu_to_le32(*field_len);

	/* n-ng template field */
	field_len = (uint32_t *)(entry.template + offset);
	offset += sizeof(*field_len);

	current_offset = offset;

	if (digest_list_filename[0] == '/')
		digest_list_filename++;

	offset += snprintf((char *)entry.template + offset,
			   entry.template_buf_len - offset, "%s/%s",
			   digest_list_dir, digest_list_filename);
	offset++;

	*field_len = (offset - current_offset);

	if (ima_canonical_fmt)
		*field_len = cpu_to_le32(*field_len);

	/* sig template field */
	field_len = (uint32_t *)(entry.template + offset);
	offset += sizeof(*field_len);

	xattr = NULL;

	ret = read_ima_xattr(-1, (char *)entry.template + current_offset,
			     &xattr, &xattr_len, &keyid, &keyid_len, &sig,
			     &sig_len, &algo);
	if (ret < 0 && (ret == -EINVAL || ret == -ENODATA))
		xattr_len = 0;
	else if (ret < 0)
		goto out;

	current_offset = offset;
	memcpy(entry.template + offset, xattr, xattr_len);
	offset += xattr_len;

	*field_len = (offset - current_offset);

	if (ima_canonical_fmt)
		*field_len = cpu_to_le32(*field_len);

	current_offset = offset;

	ret = calc_digest(entry.header.digest, entry.template, current_offset,
			  HASH_ALGO_SHA1);
	if (ret < 0)
		goto out;

	ret = write_check(fd, &entry.header, sizeof(entry.header));
	if (ret < 0)
		goto out;

	ret = write_check(fd, IMA_SIG_TEMPLATE, sizeof(IMA_SIG_TEMPLATE) - 1);
	if (ret < 0)
		goto out;

	if (ima_canonical_fmt)
		current_offset = cpu_to_le32(current_offset);

	ret = write_check(fd, &current_offset, sizeof(current_offset));
	if (ret < 0)
		goto out;

	ret = write_check(fd, entry.template, offset);
out:
	free(entry.template);
	return ret;
}
