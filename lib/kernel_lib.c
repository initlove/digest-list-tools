/*
 * Copyright (c) 2013 Dmitry Kasatkin <d.kasatkin@samsung.com>
 * Copyright (C) 2017-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: kernel_lib.c
 *      Libraries from the Linux kernel.
 */

#include <errno.h>

#include "kernel_lib.h"
#include "xattr.h"


/* from crypto/hash_info.c */
const char *const hash_algo_name[HASH_ALGO__LAST] = {
	[HASH_ALGO_MD4]         = "md4",
	[HASH_ALGO_MD5]         = "md5",
	[HASH_ALGO_SHA1]        = "sha1",
	[HASH_ALGO_RIPE_MD_160] = "rmd160",
	[HASH_ALGO_SHA256]      = "sha256",
	[HASH_ALGO_SHA384]      = "sha384",
	[HASH_ALGO_SHA512]      = "sha512",
	[HASH_ALGO_SHA224]      = "sha224",
	[HASH_ALGO_RIPE_MD_128] = "rmd128",
	[HASH_ALGO_RIPE_MD_256] = "rmd256",
	[HASH_ALGO_RIPE_MD_320] = "rmd320",
	[HASH_ALGO_WP_256]      = "wp256",
	[HASH_ALGO_WP_384]      = "wp384",
	[HASH_ALGO_WP_512]      = "wp512",
	[HASH_ALGO_TGR_128]     = "tgr128",
	[HASH_ALGO_TGR_160]     = "tgr160",
	[HASH_ALGO_TGR_192]     = "tgr192",
	[HASH_ALGO_SM3_256]     = "sm3-256",
};

const int hash_digest_size[HASH_ALGO__LAST] = {
	[HASH_ALGO_MD4]         = MD5_DIGEST_SIZE,
	[HASH_ALGO_MD5]         = MD5_DIGEST_SIZE,
	[HASH_ALGO_SHA1]        = SHA1_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_160] = RMD160_DIGEST_SIZE,
	[HASH_ALGO_SHA256]      = SHA256_DIGEST_SIZE,
	[HASH_ALGO_SHA384]      = SHA384_DIGEST_SIZE,
	[HASH_ALGO_SHA512]      = SHA512_DIGEST_SIZE,
	[HASH_ALGO_SHA224]      = SHA224_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_128] = RMD128_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_256] = RMD256_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_320] = RMD320_DIGEST_SIZE,
	[HASH_ALGO_WP_256]      = WP256_DIGEST_SIZE,
	[HASH_ALGO_WP_384]      = WP384_DIGEST_SIZE,
	[HASH_ALGO_WP_512]      = WP512_DIGEST_SIZE,
	[HASH_ALGO_TGR_128]     = TGR128_DIGEST_SIZE,
	[HASH_ALGO_TGR_160]     = TGR160_DIGEST_SIZE,
	[HASH_ALGO_TGR_192]     = TGR192_DIGEST_SIZE,
	[HASH_ALGO_SM3_256]     = SM3256_DIGEST_SIZE,
};

/* from lib/hexdump.c */

/**
 * hex_to_bin - convert a hex digit to its real value
 * @ch: ascii character represents hex digit
 *
 * hex_to_bin() converts one hex digit to its actual value or -1 in case of bad
 * input.
 */
int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

/**
 * hex2bin - convert an ascii hexadecimal string to its binary representation
 * @dst: binary result
 * @src: ascii hexadecimal string
 * @count: result length
 *
 * Return 0 on success, -1 in case of bad input.
 */
int hex2bin(u8 *dst, const char *src, size_t count)
{
	while (count--) {
		int hi = hex_to_bin(*src++);
		int lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}

#ifdef __BIG_ENDIAN__
bool ima_canonical_fmt = true;
#else
bool ima_canonical_fmt = false;
#endif

int default_func(u8 *digest, enum hash_algo algo, enum compact_types type,
                 u16 modifiers)
{
	return 0;
}

/* from ima_digest_list.c */
int ima_parse_compact_list(loff_t size, void *buf,
			   add_digest_func ima_add_digest_data_entry)
{
	u8 *digest;
	void *bufp = buf, *bufendp = buf + size;
	struct compact_list_hdr *hdr;
	size_t digest_len;
	int ret, i;

	while (bufp < bufendp) {
		if (bufp + sizeof(*hdr) > bufendp) {
			pr_err("compact list, invalid data\n");
			return -EINVAL;
		}

		hdr = bufp;

		if (hdr->version != 1) {
			pr_err("compact list, unsupported version\n");
			return -EINVAL;
		}

		if (ima_canonical_fmt) {
			hdr->type = le16_to_cpu(hdr->type);
			hdr->modifiers = le16_to_cpu(hdr->modifiers);
			hdr->algo = le16_to_cpu(hdr->algo);
			hdr->count = le32_to_cpu(hdr->count);
			hdr->datalen = le32_to_cpu(hdr->datalen);
		}

		if (hdr->algo >= HASH_ALGO__LAST)
			return -EINVAL;

		digest_len = hash_digest_size[hdr->algo];

		if (hdr->type >= COMPACT__LAST) {
			pr_err("compact list, invalid type %d\n", hdr->type);
			return -EINVAL;
		}

		bufp += sizeof(*hdr);

		for (i = 0; i < hdr->count; i++) {
			if (bufp + digest_len > bufendp) {
				pr_err("compact list, invalid data\n");
				return -EINVAL;
			}

			digest = bufp;
			bufp += digest_len;

			ret = ima_add_digest_data_entry(digest, hdr->algo,
							hdr->type,
							hdr->modifiers);
			if (ret < 0 && ret != -EEXIST)
				return ret;
		}

		if (i != hdr->count ||
		    bufp != (void *)hdr + sizeof(*hdr) + hdr->datalen) {
			pr_err("compact list, invalid data\n");
			return -EINVAL;
		}
	}

	return bufp - buf;
}
