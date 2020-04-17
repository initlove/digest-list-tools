/*
 * Copyright (C) 2017-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: lib.c
 *      Includes libraries.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/xattr.h>

#include "lib.h"


int read_file_from_path(int dirfd, const char *path, void **buf, loff_t *size)
{
	struct stat st;
	int ret = 0, fd;

	if (dirfd >= 0) {
		if (fstatat(dirfd, path, &st, 0) == -1)
			return -EACCES;

		fd = openat(dirfd, path, O_RDONLY);
	} else {
		if (stat(path, &st) == -1)
			return -EACCES;

		fd = open(path, O_RDONLY);
	}

	if (fd < 0)
		return -EINVAL;

	*buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
		    fd, 0);
	if (*buf == MAP_FAILED) {
		ret = -ENOMEM;
		goto out;
	}

	*size = st.st_size;
out:
	close(fd);
	return ret;
}

ssize_t write_check(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	while (count > 0) {
		ret = write(fd, buf, count);
		if (ret == -1) {
			printf("write() error (%s)\n", strerror(errno));
			return -EIO;
		} else if (!ret) {
			printf("write() incomplete, remaining: %zu bytes\n",
			       count);
			return -EIO;
		}

		buf += ret;
		count -= ret;
	}

	return 0;
}

struct lib *lookup_lib(struct list_head *head, const char *lib_type,
		       const char *format, int format_len)
{
	struct lib *tmp, *new;
	char lib_path[PATH_MAX + 1];
	char function[NAME_MAX + 1];
	char *format_end_ptr, *func_name_ptr;
	void *handle;
	int ret, lib_path_len;

	format_end_ptr = strchrnul(format, '-');
	func_name_ptr = memchr(format, '+', format_end_ptr - format);
	if (func_name_ptr) {
		snprintf(function, sizeof(function), "%.*s_%s",
			 (int)(format_end_ptr - func_name_ptr - 1),
			 func_name_ptr + 1, lib_type);
		format_len = func_name_ptr - format;
	} else {
		strncpy(function, lib_type, sizeof(function));
	}

	if (!list_empty(head)) {
		list_for_each_entry(tmp, head, list)
			if (!strncmp(tmp->format, format, format_len))
				return tmp;
	}

	new = calloc(1, sizeof(*new));
	if (!new)
		return new;

	new->format = malloc(format_len + 1);
	if (!new->format)
		goto err_free;

	strncpy(new->format, format, format_len);
	new->format[format_len] = '\0';

	handle = dlopen("libdigestlist-base.so", RTLD_LAZY);
	if (!handle)
		goto err_free;

	ret = dlinfo(handle, RTLD_DI_ORIGIN, lib_path);
	dlclose(handle);

	if (ret < 0)
		goto err_free;

	lib_path_len = strlen(lib_path);

	snprintf(lib_path + lib_path_len, sizeof(lib_path) - lib_path_len,
		 "/digestlist/lib%s-%s.so", lib_type, new->format);

	new->handle = dlopen(lib_path, RTLD_LAZY | RTLD_NODELETE);
	if (!new->handle) {
		snprintf(lib_path, sizeof(lib_path), "lib%s-%s.so", lib_type,
			 new->format);

		new->handle = dlopen(lib_path, RTLD_LAZY | RTLD_NODELETE);
		if (!new->handle)
			goto err_free;
	}

	
	new->func = dlsym(new->handle, function);

	if (!new->func)
		goto err_free;

	list_add_tail(&new->list, head);

	return new;
err_free:
	if (new) {
		free(new->format);
		if (new->handle)
			dlclose(new->handle);
	}

	free(new);
	return NULL;
}

void free_libs(struct list_head *head)
{
	struct lib *cur, *tmp;

	list_for_each_entry_safe(cur, tmp, head, list) {
		list_del(&cur->list);
		free(cur->format);
		dlclose(cur->handle);
		free(cur);
	}
}

int add_path_struct(char *path, struct list_head *head)
{
	struct path_struct *new;

	new = malloc(sizeof(*new));
	if (!new)
		return -ENOMEM;

	new->path = malloc(strlen(path) + 1);
	if (!new->path) {
		free(new);
		return -ENOMEM;
	}

	strcpy(new->path, path);
	list_add_tail(&new->list, head);
	return 0;
}

void move_path_structs(struct list_head *dest, struct list_head *src)
{
	struct path_struct *p, *q;

	list_for_each_entry_safe(p, q, src, list) {
		list_del(&p->list);
		list_add_tail(&p->list, dest);
	}
}

void free_path_structs(struct list_head *head)
{
	struct path_struct *cur, *tmp;

	if (list_empty(head))
		return;

	list_for_each_entry_safe(cur, tmp, head, list) {
		list_del(&cur->list);
		free(cur->path);
		free(cur);
	}
}
