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
 * File: lib.h
 *      Header of lib.h.
 */

#ifndef _LIB_H
#define _LIB_H

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "kernel_lib.h"

#define MAX_FILENAME_LENGTH 256

extern char *digest_list_path;

int calc_digest(u8 *digest, void *data, int len, enum hash_algo algo);
int calc_file_digest(char *path, u8 *digest, enum hash_algo algo);
int kernel_read_file_from_path(const char *path, void **buf, loff_t *size,
			       loff_t max_size, enum kernel_read_file_id id);

#endif /* _LIB_H */
