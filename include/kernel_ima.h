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
#include "lib.h"

#define ENFORCE_FIELDS 0x00000001
#define ENFORCE_BUFEND 0x00000002

extern int digests;
extern int ima_hash_algo;

struct compact_list_hdr {
	u16 entry_id;
	u32 count;
	u32 datalen;
} __attribute__((packed));

struct ima_field_data {
	u8 *data;
	u_int32_t len;
};

enum digest_metadata_fields {DATA_ALGO, DATA_DIGEST, DATA_SIGNATURE,
			     DATA_FILE_PATH, DATA_REF_ID, DATA_TYPE,
			     DATA__LAST};

enum digest_data_types {DATA_TYPE_COMPACT_LIST, DATA_TYPE_RPM};

enum compact_list_entry_ids {COMPACT_DIGEST, COMPACT_DIGEST_MUTABLE};

int ima_hash_setup(char *str);
int ima_get_buflen(int maxfields, struct ima_field_data *fields,
		   unsigned long *len_mask);
int ima_write_buf(void *bufstartp, void *bufendp, void **bufcurp,
		  int maxfields, struct ima_field_data *fields, int *curfields,
		  unsigned long *len_mask, int enforce_mask, char *bufname);
ssize_t ima_parse_digest_list_metadata(loff_t size, void *buf);

#endif /* _KERNEL_IMA_H */
