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
 * File: evm.c
 *      Library to calculate EVM HMAC.
 */

#include <errno.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/xattr.h>
#include <linux/magic.h>

#include "evm.h"
#include "selinux.h"

/* from security/integrity/evm/evm_crypto.c in the Linux kernel source code */

/* Protect against 'cutting & pasting' security.evm xattr, include inode
 * specific info.
 *
 * (Additional directory/file metadata needs to be added for more complete
 * protection.)
 */
static int hmac_add_misc(EVP_MD_CTX *mdctx, uid_t uid, gid_t gid, mode_t mode,
			 u8 *digest)
{
	struct h_misc {
		unsigned long ino;
		u32 generation;
		uid_t uid;
		gid_t gid;
		mode_t mode;
	} hmac_misc;

	memset(&hmac_misc, 0, sizeof(hmac_misc));

	hmac_misc.uid = uid;
	hmac_misc.gid = gid;
	hmac_misc.mode = mode;

	if (EVP_DigestUpdate(mdctx, (const u8 *)&hmac_misc,
			     sizeof(hmac_misc)) != 1)
		return -EINVAL;

	if (EVP_DigestFinal_ex(mdctx, digest, NULL) != 1)
		return -EINVAL;

	return 0;
}

/*
 * Calculate the HMAC value across the set of protected security xattrs.
 *
 * Instead of retrieving the requested xattr, for performance, calculate
 * the hmac using the requested xattr value. Don't alloc/free memory for
 * each xattr, but attempt to re-use the previously allocated memory.
 */
int evm_calc_hmac_or_hash(enum hash_algo algo, u8 *digest,
			  int lsm_label_len, char *lsm_label,
			  int ima_digest_len, u8 *ima_digest,
			  int caps_bin_len, u8 *caps_bin,
			  uid_t uid, gid_t gid, mode_t mode)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	int ret = -EINVAL;

	OpenSSL_add_all_algorithms();

	md = EVP_get_digestbyname(hash_algo_name[algo]);
	if (!md)
		goto out;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
		goto out;

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
		goto out_mdctx;

	if (lsm_label &&
	    EVP_DigestUpdate(mdctx, (const u8 *)lsm_label, lsm_label_len) != 1)
		goto out_mdctx;

	if (EVP_DigestUpdate(mdctx, (const u8 *)ima_digest,
			     ima_digest_len) != 1)
		goto out_mdctx;

	if (EVP_DigestUpdate(mdctx, caps_bin, caps_bin_len) != 1)
		goto out_mdctx;

	if (hmac_add_misc(mdctx, uid, gid, mode, digest) < 0)
		goto out_mdctx;

	ret = 0;
out_mdctx:
	EVP_MD_CTX_destroy(mdctx);
out:
	EVP_cleanup();
	return ret;
}
