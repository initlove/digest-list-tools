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
 * File: kernel_ima.h
 *      IMA functions header
 */

#ifndef _KERNEL_IMA_H
#define _KERNEL_IMA_H

#include "kernel_lib.h"
#include "securityfs.h"
#include "lib.h"

#define min(x,y) x > y ? y : x

#define ENFORCE_FIELDS 0x00000001
#define ENFORCE_BUFEND 0x00000002

#define DIGEST_FLAG_DIGEST_ALGO 0x01
#define DIGEST_FLAG_IMMUTABLE	0x02

#define PARSER_STRING "~parser~\n"
#define REQ_PARSER_VERSION 1

#define REQ_METADATA_VERSION 1

#define IMA_MAX_DIGEST_SIZE	64

#define IMA_MEASURE		0x00000001
#define IMA_APPRAISE		0x00000004

extern int ima_hash_algo;
extern int ima_canonical_fmt;
extern int current;
extern int parser_task;
extern int ima_digest_list_actions;

struct ima_field_data {
	u8 *data;
	u_int32_t len;
};

enum compact_list_entry_ids {COMPACT_DIGEST, COMPACT_DIGEST_MUTABLE,
			     COMPACT_DIGEST_LIST};

struct compact_list_hdr {
	u16 entry_id;
	u16 algo;
	u32 count;
	u32 datalen;
} __attribute__((packed));

enum digest_metadata_fields {DATA_ALGO, DATA_TYPE, DATA_TYPE_EXT,
			     DATA_DIGEST_ALGO, DATA_DIGEST,
			     DATA_SIG_FMT, DATA_SIG,
			     DATA_FILE_PATH, DATA_LENGTH, DATA__LAST};

enum data_sig_formats {SIG_FMT_NONE, SIG_FMT_IMA, SIG_FMT_PGP, SIG_FMT_PKCS7};

enum digest_data_types {DATA_TYPE_HEADER, DATA_TYPE_DIGEST_LIST, DATA_TYPE_KEY,
			DATA_TYPE_PARSER, DATA_TYPE_REG_FILE};

enum digest_data_sub_types {DATA_SUB_TYPE_COMPACT_LIST,
			    DATA_SUB_TYPE_RPM,
			    DATA_SUB_TYPE_DEB_RELEASE,
			    DATA_SUB_TYPE_DEB_PACKAGES_GZ,
			    DATA_SUB_TYPE_DEB_PACKAGE,
			    DATA_SUB_TYPE__LAST};

int ima_hash_setup(char *str);
int ima_get_buflen(int maxfields, struct ima_field_data *fields,
		   unsigned long *len_mask);
int ima_write_buf(void *bufstartp, void *bufendp, void **bufcurp,
		  int maxfields, struct ima_field_data *fields, int *curfields,
		  unsigned long *len_mask, int enforce_mask, char *bufname);
int ima_check_parser(u8 *data, u32 data_len, u8 **digest, u16 *digest_algo);
ssize_t ima_parse_digest_list_metadata(loff_t size, void *buf);

typedef int (*callback_func)(void *ctx, char *line);

#endif /* _KERNEL_IMA_H */
