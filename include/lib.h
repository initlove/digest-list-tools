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

#define MAX_PATH_LENGTH 2048

extern char *digest_lists_dir_path;
extern int parse_metadata, remove_file, set_ima_algo;

int calc_digest(u8 *digest, void *data, int len, enum hash_algo algo);
int calc_file_digest(u8 *digest, char *path, enum hash_algo algo);
int check_digest(void *data, int len, char *path,
		 enum hash_algo algo, u8 *input_digest);
int read_file_from_path(const char *path, void **buf, loff_t *size);
ssize_t write_check(int fd, const void *buf, size_t count);
void hexdump(u8 *buf, int len);

#endif /* _LIB_H */
