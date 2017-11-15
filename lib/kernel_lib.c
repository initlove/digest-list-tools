/*
 * Copyright (c) 2013 Dmitry Kasatkin <d.kasatkin@samsung.com>
 * Copyright (C) 2017 Huawei Technologies Duesseldorf GmbH
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
#include "kernel_lib.h"

/* from lib/bitmap.c */
void bitmap_zero(unsigned long *dst, unsigned int nbits)
{
	if (small_const_nbits(nbits))
		*dst = 0UL;
	else {
		unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
		memset(dst, 0, len);
	}
}

void bitmap_set(unsigned long *map, unsigned int start, int len)
{
	unsigned long *p = map + BIT_WORD(start);
	const unsigned int size = start + len;
	int bits_to_set = BITS_PER_LONG - (start % BITS_PER_LONG);
	unsigned long mask_to_set = BITMAP_FIRST_WORD_MASK(start);

	while (len - bits_to_set >= 0) {
		*p |= mask_to_set;
		len -= bits_to_set;
		bits_to_set = BITS_PER_LONG;
		mask_to_set = ~0UL;
		p++;
	}
	if (len) {
		mask_to_set &= BITMAP_LAST_WORD_MASK(size);
		*p |= mask_to_set;
	}
}

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
