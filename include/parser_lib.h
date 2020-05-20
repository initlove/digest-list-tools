/*
 * Copyright (C) 2019-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: parser_lib.h
 *      Header of parser_lib.c
 */

#ifndef _PARSER_LIB_H
#define _PARSER_LIB_H

#include "compact_list.h"

int add_digest(int fd, struct list_head *head, u16 type, u16 modifiers,
	       u16 algo, u8 *digest);
int calc_metadata_digest(int fd, struct list_head *head, u16 type,
			 u16 modifiers, u16 algo, u8 *digest, u8 *evm_digest,
			 char *path, uid_t uid, gid_t gid, mode_t mode,
			 char *obj_label, char *caps);
int add_metadata_digest(int fd, struct list_head *head, u16 modifiers,
			u8 *evm_digest);
int add_ima_xattr(int fd, struct list_head *head, u16 type, u16 modifiers,
		  u16 algo, u8 *digest, char *path);
int check_repair_xattr(char *path, char *xattr_name, void *xattr_value,
		       int xattr_value_len, int ima_algo, int modifiers,
		       int repair);
int check_repair_attr(char *path, uid_t uid, gid_t gid, mode_t mode,
		      int repair);

#endif /*_PARSER_LIB_H*/
