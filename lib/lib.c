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


static int read_file_from_path_common(int dirfd, const char *path, void **buf,
				      loff_t *size, bool shared)
{
	struct stat st;
	int mmap_flags = MAP_PRIVATE;
	int ret = 0, fd, open_flags = O_RDONLY;

	if (shared) {
		open_flags = O_RDWR;
		mmap_flags = MAP_SHARED;
	}

	if (dirfd >= 0) {
		if (fstatat(dirfd, path, &st, 0) == -1)
			return -EACCES;

		fd = openat(dirfd, path, open_flags);
	} else {
		if (stat(path, &st) == -1)
			return -EACCES;

		fd = open(path, open_flags);
	}

	if (fd < 0)
		return -EINVAL;

	*buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, mmap_flags, fd,
		    0);
	if (*buf == MAP_FAILED) {
		ret = -ENOMEM;
		goto out;
	}

	*size = st.st_size;
out:
	close(fd);
	return ret;
}

int read_file_from_path(int dirfd, const char *path, void **buf, loff_t *size)
{
	return read_file_from_path_common(dirfd, path, buf, size, false);
}

int read_write_file_from_path(int dirfd, const char *path, void **buf,
			      loff_t *size)
{
	return read_file_from_path_common(dirfd, path, buf, size, true);
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

int copy_file(char *src, char *dest)
{
	void *data;
	loff_t size;
	int ret, fd;

	ret = read_file_from_path(-1, src, &data, &size);
	if (ret < 0)
		return ret;

	fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		goto out;

	ret = write_check(fd, data, size);
	close(fd);
out:
	munmap(data, size);
	return ret;
}

struct lib *lookup_lib(struct list_head *head, const char *lib_type,
		       const char *format, int format_len)
{
	struct lib *tmp, *new;
	char lib_path[PATH_MAX + 1];
	char function[NAME_MAX + 1];
	const char *format_end_ptr, *func_name_ptr;
	void *handle;
	int ret, lib_path_len;

	format_end_ptr = format + format_len;
	func_name_ptr = memchr(format, '+', format_len);
	if (func_name_ptr) {
		snprintf(function, sizeof(function), "%.*s_%s",
			 (int)(format_end_ptr - func_name_ptr - 1),
			 func_name_ptr + 1, lib_type);
		format_len = func_name_ptr - format;
	} else {
		strncpy(function, lib_type, sizeof(function) - 1);
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
#ifdef UNIT_TESTING
	handle = dlopen("libdigestlist-base-test.so", RTLD_LAZY);
#else
	handle = dlopen("libdigestlist-base.so", RTLD_LAZY);
#endif
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

int add_path_struct(char *path, char **attrs, struct list_head *head)
{
	struct path_struct *new;
	int i;

	new = calloc(1, sizeof(*new));
	if (!new)
		return -ENOMEM;

	if (attrs) {
		/* skip the path */
		for (i = 1; i < ATTR__LAST; i++) {
			new->attrs[i] = strdup(attrs[i]);
			if (!new->attrs[i])
				goto err;
		}
	}

	new->path = malloc(strlen(path) + 1);
	if (!new->path)
		goto err;

	strcpy(new->path, path);
	list_add_tail(&new->list, head);
	return 0;
err:
	for (i = 0; i < ATTR__LAST; i++)
		free(new->attrs[i]);

	free(new);
	return -ENOMEM;
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
	int i;

	if (list_empty(head))
		return;

	list_for_each_entry_safe(cur, tmp, head, list) {
		list_del(&cur->list);

		for (i = 0; i < ATTR__LAST; i++)
			free(cur->attrs[i]);

		free(cur->path);
		free(cur);
	}
}
