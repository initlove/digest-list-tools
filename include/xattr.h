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
 * File: xattr.h
 *      Header of xattr.c.
 */

#ifndef _XATTR_H
#define _XATTR_H

#include "lib.h"

int write_ima_xattr(int dirfd, char *path, u8 *keyid, size_t keyid_len,
		    u8 *sig, size_t sig_len, enum hash_algo algo);
int read_ima_xattr(int dirfd, char *path, u8 **buf,
		   u8 **keyid, size_t *keyid_len,
		   u8 **sig, size_t *sig_len, enum hash_algo *algo);

#endif /*_XATTR_H*/
