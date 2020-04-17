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
 * File: xattr.c
 *      Write IMA xattrs.
 */

#include <errno.h>
#include <unistd.h>
#include <sys/xattr.h>

#include "xattr.h"


int write_ima_xattr(int dirfd, char *path, u8 *keyid, size_t keyid_len,
		    u8 *sig, size_t sig_len, enum hash_algo algo)
{
	struct signature_v2_hdr *hdr;
	u8 *xattr_buf;
	size_t xattr_buf_len;
	int ret, fd;

	xattr_buf_len = sizeof(*hdr) + sig_len;
	xattr_buf = calloc(sizeof(u8), xattr_buf_len);
	if (!xattr_buf)
		return -ENOMEM;

	hdr = (struct signature_v2_hdr *)xattr_buf;
	hdr->type = EVM_IMA_XATTR_DIGSIG;
	hdr->version = 2;
	hdr->hash_algo = algo;
	if (keyid_len)
		memcpy(&hdr->keyid, keyid, keyid_len);
	hdr->sig_size = cpu_to_be16(sig_len);
	memcpy(&hdr->sig, sig, sig_len);

	if (dirfd != -1) {
		fd = openat(dirfd, path, O_RDONLY);
		if (fd < 0) {
			printf("Cannot open %s\n", path);
			ret = fd;
			goto out;
		}

		ret = fsetxattr(fd, XATTR_NAME_IMA,
				xattr_buf, xattr_buf_len, 0);
		close(fd);
	} else {
		ret = setxattr(path, XATTR_NAME_IMA,
			       xattr_buf, xattr_buf_len, 0);
	}
out:
	if (ret < 0)
		printf("Cannot add %s xattr\n", XATTR_NAME_IMA);

	free(xattr_buf);
	return ret;
}

int read_ima_xattr(int dirfd, char *path, u8 **buf,
		   u8 **keyid, size_t *keyid_len,
		   u8 **sig, size_t *sig_len, enum hash_algo *algo)
{
	struct signature_v2_hdr *hdr;
	ssize_t ret;
	int fd;

	fd = openat(dirfd, path, O_RDONLY);
	if (fd < 0) {
		printf("Cannot open %s\n", path);
		return fd;
	}

	ret = fgetxattr(fd, XATTR_NAME_IMA, NULL, 0);
	if (ret < 0)
		return ret;

	*buf = malloc(ret);
	if (!*buf)
		return -ENOMEM;

	ret = fgetxattr(fd, XATTR_NAME_IMA, *buf, ret);
	if (ret < 0)
		return ret;

	hdr = (struct signature_v2_hdr *)*buf;

	if (hdr->type != EVM_IMA_XATTR_DIGSIG)
		return -EINVAL;

	if (hdr->version != 2)
		return -EINVAL;

	*algo = hdr->hash_algo;
	*keyid = (u8 *)&hdr->keyid;
	*keyid_len = sizeof(hdr->keyid);
	*sig = hdr->sig;
	*sig_len = be16_to_cpu(hdr->sig_size);
	return 0;
}
