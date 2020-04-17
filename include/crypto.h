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
 * File: crypto.h
 *      Header of crypto.c.
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "lib.h"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#define MAX_SIGNATURE_SIZE 1024

int calc_digest(u8 *digest, void *data, u64 len, enum hash_algo algo);
int calc_file_digest(u8 *digest, int dirfd, char *path, enum hash_algo algo);
int sign_files(int dirfd, struct list_head *head, char *key_path,
	       char *keypass, enum hash_algo algo);

struct key_struct {
	struct list_head list;
	RSA *key;
	u8 keyid[4];
};

void free_keys(struct list_head *head);
struct key_struct *new_key(struct list_head *head, int dirfd, char *key_path,
			   char *keypass, bool private);
struct key_struct *lookup_key(struct list_head *head, int dirfd, char *key_path,
			      u8 *keyid);
int verify_file(struct list_head *head, int dirfd, char *filename);
int verify_sig(struct list_head *head, int dirfd, u8 *sig, int sig_len,
               u8 *digest, enum hash_algo algo);

#endif /*_CRYPTO_H*/
