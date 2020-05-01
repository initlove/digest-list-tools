/*
 * Copyright (C) 2017-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: xattr.h
 *      Header of xattr.c.
 */

#ifndef _XATTR_H
#define _XATTR_H

#include "lib.h"

int write_ima_xattr(int dirfd, char *path, u8 *keyid, size_t keyid_len,
		    u8 *sig, size_t sig_len, enum hash_algo algo);
int write_evm_xattr(char *path, enum hash_algo algo);
int parse_ima_xattr(u8 *buf, size_t buf_len, u8 **keyid, size_t *keyid_len,
		    u8 **sig, size_t *sig_len, enum hash_algo *algo);
int read_ima_xattr(int dirfd, char *path, u8 **buf, size_t *buf_len,
		   u8 **keyid, size_t *keyid_len, u8 **sig, size_t *sig_len,
		   enum hash_algo *algo);
int gen_write_ima_xattr(u8 *buf, int *buf_len, char *path, u8 algo, u8 *digest,
			bool immutable, bool write);

#endif /*_XATTR_H*/
