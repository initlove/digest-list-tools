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
 * File: lib.h
 *      Library header.
 */

#ifndef _LIB_H
#define _LIB_H

#include <dlfcn.h>
#include <dirent.h>

#include "list.h"
#include "kernel_lib.h"

#ifdef UNIT_TESTING
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#endif


#define SYSFS_PATH "/sys"
#define SECURITYFS_PATH SYSFS_PATH "/kernel/security"
#define IMA_SECURITYFS_PATH SECURITYFS_PATH "/ima"

int read_file_from_path(int dirfd, const char *path, void **buf, loff_t *size);
int read_write_file_from_path(int dirfd, const char *path, void **buf,
			      loff_t *size);
ssize_t write_check(int fd, const void *buf, size_t count);
int copy_file(char *src, char *dest);

struct lib {
	struct list_head list;
	char *format;
	void *handle;
	void *func;
};

struct lib *lookup_lib(struct list_head *head, const char *lib_type,
		       const char *format, int format_len);
void free_libs(struct list_head *head);

enum file_attrs { ATTR_PATH, ATTR_MODE, ATTR_UNAME, ATTR_GNAME, ATTR_CAPS,
		  ATTR__LAST };

struct path_struct {
	struct list_head list;
	char *attrs[ATTR__LAST];
	char *path;
};

int add_path_struct(char *path, char **attrs, struct list_head *head);
void move_path_structs(struct list_head *dest, struct list_head *src);
void free_path_structs(struct list_head *head);

#endif /*_LIB_H*/
