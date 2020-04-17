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
 * File: evm.h
 *      Header of evm.c.
 */

#ifndef _EVM_H
#define _EVM_H

#include "kernel_lib.h"
#include "compact_list.h"

int evm_calc_hmac_or_hash(enum hash_algo algo, u8 *digest,
			  int lsm_label_len, char *lsm_label,
			  int ima_digest_len, u8 *ima_digest,
			  int caps_bin_len, u8 *caps_bin,
			  uid_t uid, gid_t gid, mode_t mode);

#endif /*_EVM_H*/
