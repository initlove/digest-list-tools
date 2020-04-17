/*
 * Copyright (C) 1991, 1992 Linus Torvalds
 * Copyright (C) 2002 Nadia Yvette Chambers, IBM
 * Copyright (C) 2007 rPath, Inc. - All Rights Reserved
 * Copyright (c) 2013 Dmitry Kasatkin <d.kasatkin@samsung.com>
 * Copyright (C) 2017-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: kernel_lib.h
 *      Header of kernel_lib.c
 */

#ifndef _KERNEL_LIB_H
#define _KERNEL_LIB_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <linux/xattr.h>
#ifdef __BIG_ENDIAN__
#include <linux/byteorder/big_endian.h>
#else
#include <linux/byteorder/little_endian.h>
#endif

#include "list.h"
#include "config.h"

/* kernel types */
typedef u_int8_t u8;
typedef u_int16_t u16;
typedef u_int32_t u32;
typedef u_int64_t u64;
#ifndef bool
typedef int bool;
#endif

typedef unsigned long atomic_long_t;

static inline void atomic_long_inc(atomic_long_t *x)
{
	(*x)++;
}

#define true 1
#define false 0

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define S_IWUGO         (S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO         (S_IXUSR|S_IXGRP|S_IXOTH)

#define pr_err printf
#define pr_info printf

#ifdef DEBUG
#define pr_devel printf
#define pr_debug printf
#else
static inline void pr_devel(const char *__restrict __format, ...)
{
}
static inline void pr_debug(const char *__restrict __format, ...)
{
}
#endif /* DEBUG */

#define rcu_read_lock()
#define rcu_read_unlock()

#define GFP_KERNEL 0
#define kmalloc(x, y) malloc(x)

/* endianness conversion */
#define be32_to_cpu __be32_to_cpu
#define be16_to_cpu __be16_to_cpu
#define cpu_to_be32 __cpu_to_be32
#define cpu_to_be16 __cpu_to_be16
#define le16_to_cpu __le16_to_cpu
#define le32_to_cpu __le32_to_cpu
#define le64_to_cpu __le64_to_cpu
#define cpu_to_le16 __cpu_to_le16
#define cpu_to_le32 __cpu_to_le32
#define cpu_to_le64 __cpu_to_le64

/* crypto */
#define CRYPTO_MAX_ALG_NAME             128

#define MD5_DIGEST_SIZE         16
#define SHA1_DIGEST_SIZE        20
#define RMD160_DIGEST_SIZE      20
#define SHA256_DIGEST_SIZE      32
#define SHA384_DIGEST_SIZE      48
#define SHA512_DIGEST_SIZE      64
#define SHA224_DIGEST_SIZE      28
#define RMD128_DIGEST_SIZE      16
#define RMD256_DIGEST_SIZE      32
#define RMD320_DIGEST_SIZE      40
#define WP512_DIGEST_SIZE 64
#define WP384_DIGEST_SIZE 48
#define WP256_DIGEST_SIZE 32
#define TGR192_DIGEST_SIZE 24
#define TGR160_DIGEST_SIZE 20
#define TGR128_DIGEST_SIZE 16
#define SM3256_DIGEST_SIZE 32

enum hash_algo {
	HASH_ALGO_MD4,
	HASH_ALGO_MD5,
	HASH_ALGO_SHA1,
	HASH_ALGO_RIPE_MD_160,
	HASH_ALGO_SHA256,
	HASH_ALGO_SHA384,
	HASH_ALGO_SHA512,
	HASH_ALGO_SHA224,
	HASH_ALGO_RIPE_MD_128,
	HASH_ALGO_RIPE_MD_256,
	HASH_ALGO_RIPE_MD_320,
	HASH_ALGO_WP_256,
	HASH_ALGO_WP_384,
	HASH_ALGO_WP_512,
	HASH_ALGO_TGR_128,
	HASH_ALGO_TGR_160,
	HASH_ALGO_TGR_192,
	HASH_ALGO_SM3_256,
	HASH_ALGO__LAST
};

/* from crypto/hash_info.c */
extern const char *const hash_algo_name[HASH_ALGO__LAST];
extern const int hash_digest_size[HASH_ALGO__LAST];

/* hash */
#define BIT_PER_LONG SIZEOF_LONG * 8

#if BIT_PER_LONG == 32
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_32
#define hash_long(val, bits) hash_32(val, bits)
#elif BIT_PER_LONG == 64
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_64
#else
#error Wordsize not 32 or 64
#endif

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

#ifndef HAVE_ARCH__HASH_32
#define __hash_32 __hash_32_generic
#endif
static inline u32 __hash_32_generic(u32 val)
{
	return val * GOLDEN_RATIO_32;
}

#ifndef HAVE_ARCH_HASH_32
#define hash_32 hash_32_generic
#endif
static inline u32 hash_32_generic(u32 val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return __hash_32(val) >> (32 - bits);
}

#ifndef HAVE_ARCH_HASH_64
#define hash_64 hash_64_generic
#endif
static __always_inline u32 hash_64_generic(u64 val, unsigned int bits)
{
#if BITS_PER_LONG == 64
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return val * GOLDEN_RATIO_64 >> (64 - bits);
#else
	/* Hash 64 bits using only 32x32-bit multiply. */
	return hash_32((u32)val ^ __hash_32(val >> 32), bits);
#endif
}

static inline u32 hash_ptr(const void *ptr, unsigned int bits)
{
	return hash_long((unsigned long)ptr, bits);
}

/* This really should be called fold32_ptr; it does no hashing to speak of. */
static inline u32 hash32_ptr(const void *ptr)
{
	unsigned long val = (unsigned long)ptr;

#if BITS_PER_LONG == 64
	val ^= (val >> 32);
#endif
	return (u32)val;
}

/* from kernel.h */
int hex2bin(u8 *dst, const char *src, size_t count);

/* from xattr.h */
#define XATTR_IMA_ALGO_SUFFIX "ima_algo"
#define XATTR_NAME_IMA_ALGO XATTR_SECURITY_PREFIX XATTR_IMA_ALGO_SUFFIX

/* from ima.h */
extern bool ima_canonical_fmt;

#define IMA_HASH_BITS 9
#define IMA_MEASURE_HTABLE_SIZE (1 << IMA_HASH_BITS)

static inline unsigned long ima_hash_key(u8 *digest)
{
	return hash_long(*digest, IMA_HASH_BITS);
}

struct ima_h_table {
	atomic_long_t len;	/* number of stored measurements in the list */
	atomic_long_t violations;
	struct hlist_head queue[IMA_MEASURE_HTABLE_SIZE];
};

/* from integrity.h */
enum evm_ima_xattr_type {
	IMA_XATTR_DIGEST = 0x01,
	EVM_XATTR_HMAC,
	EVM_IMA_XATTR_DIGSIG,
	IMA_XATTR_DIGEST_NG,
	EVM_XATTR_PORTABLE_DIGSIG,
	IMA_XATTR_LAST
};

enum evm_ima_sig_fmt {
	SIG_FMT_IMA,
	SIG_FMT_PGP,
	SIG_FMT__LAST,
};

struct signature_v2_hdr {
	uint8_t type;		/* xattr type */
	uint8_t version;	/* signature format version */
	uint8_t	hash_algo;	/* Digest algorithm [enum hash_algo] */
	__be32 keyid;		/* IMA key identifier - not X509/PGP specific */
	__be16 sig_size;	/* signature size */
	uint8_t sig[0];		/* signature payload */
} __attribute__((packed));

struct evm_ima_xattr_data {
	uint8_t type;
	uint8_t digest[SHA512_DIGEST_SIZE + 1];
} __attribute__((packed));

/* from integrity.h */
enum compact_types { COMPACT_KEY, COMPACT_PARSER, COMPACT_FILE,
		     COMPACT_METADATA, COMPACT__LAST };
enum compact_modifiers { COMPACT_MOD_IMMUTABLE, COMPACT_MOD__LAST };

struct ima_digest {
	struct hlist_node hnext;
	struct list_head list;
	enum hash_algo algo;
	enum compact_types type;
	u16 modifiers;
	u8 digest[0];
};

/* from ima_digest_list.c */
struct compact_list_hdr {
	u8 version;
	u8 _reserved;
	u16 type;
	u16 modifiers;
	u16 algo;
	u32 count;
	u32 datalen;
} __attribute__((packed));

typedef int (*add_digest_func)(u8 *digest, enum hash_algo algo,
			       enum compact_types type, u16 modifiers);

int default_func(u8 *digest, enum hash_algo algo, enum compact_types type,
                 u16 modifiers);

int ima_parse_compact_list(loff_t size, void *buf,
			   add_digest_func ima_add_digest_data_entry,
			   enum hash_algo *algo);

struct ima_digest *ima_lookup_digest(u8 *digest, enum hash_algo algo);
int ima_add_digest_data_entry_kernel(u8 *digest, enum hash_algo algo,
				     enum compact_types type, u16 modifiers);

#endif /* _KERNEL_LIB_H */
