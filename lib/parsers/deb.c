/*
 * Copyright © 2000 Ben Collins <bcollins@debian.org>
 * Copyright © 2014, 2016-2017 Guillem Jover <guillem@debian.org>
 * Copyright (C) 2018 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 *  Roberto Sassu <roberto.sassu@huawei.com>
 *  Ben Collins <bcollins@debian.org>
 *  Mark Adler
 *  Tim Kientzle
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: deb.c
 *      Parses DEB packages and metadata.
 */
#include <stdio.h>
#include <unistd.h>
#include <ar.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <zlib.h>

#include "kernel_ima.h"

#define min(x,y) x > y ? y : x

/**************
 * DEB PARSER *
 **************/
#define DPKG_AR_MAGIC "!<arch>\n"
#define DPKG_AR_FMAG  "`\n"

#define CTAR(x) "control.tar" # x

static const char ver_magic_member[] = "debian-binary";
static const char *ver_ctrl_members[] = {
	CTAR(), CTAR(.gz), CTAR(.xz), NULL
};

struct dpkg_ar_hdr {
	char ar_name[16]; /* Member file name, sometimes / terminated. */
	char ar_date[12]; /* File date, decimal seconds since Epoch.  */
	char ar_uid[6], ar_gid[6]; /* User and group IDs, in ASCII decimal.  */
	char ar_mode[8]; /* File mode, in ASCII octal.  */
	char ar_size[10]; /* File size, in ASCII decimal.  */
	char ar_fmag[2];
};

static void dpkg_ar_normalize_name(struct dpkg_ar_hdr *arh)
{
	char *name = arh->ar_name;
	int i;

	/* Remove trailing spaces from the member name. */
	for (i = sizeof(arh->ar_name) - 1; i >= 0 && name[i] == ' '; i--)
		name[i] = '\0';

	/* Remove optional slash terminator (on GNU-style archives). */
	if (i >= 0 && name[i] == '/')
		name[i] = '\0';
}

static off_t dpkg_ar_member_get_size(struct dpkg_ar_hdr *arh)
{
	const char *str = arh->ar_size;
	int len = sizeof(arh->ar_size);
	off_t size = 0;

	while (len && *str == ' ')
		str++, len--;

	while (len--) {
		if (*str == ' ')
			break;
		if (*str < '0' || *str > '9') {
			pr_err("invalid character '%c'\n", *str);
			return -EINVAL;
		}

		size *= 10;
		size += *str++ - '0';
	}

	return size;
}

static bool dpkg_ar_member_is_illegal(struct dpkg_ar_hdr *arh)
{
	return memcmp(arh->ar_fmag, DPKG_AR_FMAG, sizeof(arh->ar_fmag)) != 0;
}

static int findMember(loff_t buf_len, void *buf, const char *name,
		      void **member_ptr, off_t *member_len)
{
	void *buf_ptr = buf, *buf_end = buf + buf_len;
	char magic[SARMAG + 1];
	struct dpkg_ar_hdr *arh;
	off_t mem_len;
	size_t len = strlen(name);

	if (len > sizeof(arh->ar_name)) {
		pr_debug("findMember: '%s' is too long to be an archive member "
			 "name\n", name);
		return -EINVAL;
	}

	memcpy(magic, buf_ptr, SARMAG);
	magic[SARMAG] = '\0';
	buf_ptr += SARMAG;

	if (strcmp(magic, ARMAG) != 0) {
		pr_debug("findMember: archive has bad magic");
		return -EINVAL;
	}

	do {
		if (buf_len < sizeof(arh)) {
			pr_err("findMember: error while parsing archive "
			       "header\n");
			return -EINVAL;
		}

		arh = (struct dpkg_ar_hdr *)buf_ptr;
		buf_ptr += sizeof(struct dpkg_ar_hdr);

		if (dpkg_ar_member_is_illegal(arh)) {
			pr_err("findMember: archive appears to be corrupt, "
			       "fmag incorrect\n");
			return -EINVAL;
		}

		dpkg_ar_normalize_name(arh);
		mem_len = dpkg_ar_member_get_size(arh);
		if (mem_len < 0)
			return mem_len;

		if (strncmp(arh->ar_name, name, len) == 0 &&
		    strnlen(arh->ar_name, sizeof(arh->ar_name)) == len) {
			*member_ptr = buf_ptr;
			*member_len = mem_len;
			return 0;
		}

		/* Skip to the start of the next member, and try again. */
		if (buf_ptr + mem_len + (mem_len & 1) > buf_end) {
			pr_err("findMember: error while skipping member "
			       "data\n");
			return -EINVAL;
		}

		buf_ptr += mem_len + (mem_len & 1);
	} while (buf_ptr < buf_end);

	return -ENOENT;
}

/**********
 * GUNZIP *
 **********/
static z_stream strm;
static bool finished = false;

static int init_gz(loff_t input_len, void *input)
{
	int ret;

	/* allocate inflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = input_len;
	strm.next_in = input;

	ret = inflateInit2(&strm, 31);
	if (ret != Z_OK)
		return -EINVAL;

	finished = false;
	return ret;
}

static loff_t read_gz(loff_t output_len, void *output)
{
	int ret;

	if (finished)
		return -ENODATA;

	strm.avail_out = output_len;

	while (strm.avail_out > 0 && !finished) {
		strm.next_out = output + output_len - strm.avail_out;

		ret = inflate(&strm, Z_NO_FLUSH);
		assert(ret != Z_STREAM_ERROR); /* state not clobbered */

		switch (ret) {
		case Z_NEED_DICT:
			ret = Z_DATA_ERROR;    /* and fall through */
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			return -EINVAL;
		case Z_STREAM_END:
			finished = true;
		}
	}

	return output_len - strm.avail_out;
}

static int ima_getline_gz(int buff_len, char *buff, char **buff_ptr,
			  char **line_ptr, int chunk_len)
{
	char *newline_ptr;
	int ret, to_read, i, len = 0;

	if (*buff_ptr > buff)
		goto parse;
read:
	to_read = buff_len - (*buff_ptr - buff) - 1;
	if (chunk_len) {
		if (to_read < chunk_len) {
			pr_err("Not enough space, required: %d, current: %d\n",
			       chunk_len, to_read);
			return -EINVAL;
		}

		to_read = min(chunk_len, to_read);
	}

	ret = read_gz(to_read, *buff_ptr);
	if (ret < 0)
		return ret;

	if (chunk_len && ret != chunk_len) {
		pr_err("Short read, expected: %d, current: %d\n",
		       chunk_len, ret);
		return -EIO;
	}

	for (i = 0; i < ret; i++)
		if ((*buff_ptr)[i] == '\0')
			(*buff_ptr)[i] = '0';

	(*buff_ptr)[ret] = '\0';
	*buff_ptr = buff;
parse:
	newline_ptr = strchr(*buff_ptr, '\n');
	if (!newline_ptr) {
		if (*buff_ptr > buff) {
			memmove(buff, *buff_ptr, strlen(*buff_ptr) + 1);
			*buff_ptr = buff;
		}

		if (*buff_ptr + strlen(*buff_ptr) + chunk_len >= buff + buff_len - 1) {
			len += strlen(*buff_ptr);
			*buff_ptr = buff;
		} else {
			*buff_ptr = *buff_ptr + strlen(*buff_ptr);
		}

		goto read;
	}

	*newline_ptr = '\0';
	*line_ptr = *buff_ptr;
	len += newline_ptr - *line_ptr + 1;
	*buff_ptr = newline_ptr + 1;
	if (*buff_ptr == buff + buff_len - 1)
		*buff_ptr = buff;

	return len;
}

static int end_gz(void)
{
	(void)inflateEnd(&strm);
	return (finished ? 0 : -EINVAL);
}

/*********
 * UNTAR *
 *********/
static int parseoct(const char *p, size_t n)
{
	int i = 0;

	while ((*p < '0' || *p > '7') && n > 0) {
		++p;
		--n;
	}
	while (*p >= '0' && *p <= '7' && n > 0) {
		i *= 8;
		i += *p - '0';
		++p;
		--n;
	}
	return (i);
}

static int is_end_of_archive(const char *p)
{
	int n;
	for (n = 511; n >= 0; --n)
		if (p[n] != '\0')
			return (0);
	return (1);
}

static int verify_checksum(const char *p)
{
	int n, u = 0;
	for (n = 0; n < 512; ++n) {
		if (n < 148 || n > 155)
			/* Standard tar checksum adds unsigned bytes. */
			u += ((unsigned char *)p)[n];
		else
			u += 0x20;

	}
	return (u == parseoct(p + 148, 8));
}

#define MD5SUMS_LINE_MAX_LEN hash_digest_size[HASH_ALGO_MD5] + 2 + PATH_MAX + 2
#define CHUNKS DIV_ROUND_UP(MD5SUMS_LINE_MAX_LEN, 512)

static int untar(void *ctx, callback_func func)
{
	char buff[512 * (CHUNKS + 1) + 1], *buff_ptr, *line_ptr;
	int filesize, ret = -EINVAL, func_ret;
	bool end_archive = false;

	for (;;) {
		bool parse = false;

		ret = read_gz(512, buff);
		if (ret < 512) {
			if (ret == -ENODATA && end_archive) {
				ret = 0;
				break;
			}

			pr_err("Short read : expected 512, got %d\n", ret);
			break;
		}
		if (is_end_of_archive(buff)) {
			end_archive = true;
			continue;
		}
		if (!verify_checksum(buff)) {
			pr_err("Checksum failure\n");
			break;
		}
		filesize = parseoct(buff + 124, 12);
		switch (buff[156]) {
		case '0' + 1 ... '0' + 6:
			break;
		default:
			if (strcmp(buff + 2, "md5sums") == 0)
				parse = true;
			break;
		}

		buff_ptr = buff;

		while (filesize > 0) {
			ret = ima_getline_gz(sizeof(buff), buff, &buff_ptr,
					     &line_ptr, 512);
			if (ret < 0) {
				if (ret != -ENODATA)
					return ret;

				break;
			}

			if (parse && func) {
				func_ret = func(ctx, line_ptr);
				if (func_ret < 0)
					return func_ret;
			}

			filesize -= ret;
		}
	}

	return ret;
}

int ima_parse_deb_package(loff_t size, void *buf, u16 data_algo, void *ctx,
			  callback_func func)
{
	void *member_ptr;
	off_t member_len;
	int ret, i;

	ret = findMember(size, buf, ver_magic_member, &member_ptr, &member_len);
	if (ret < 0)
		return ret;

	for (i = 0; ver_ctrl_members[i]; i++) {
		ret = findMember(size, buf, ver_ctrl_members[i],
				 &member_ptr, &member_len);
		if (ret < 0 && ret != -ENOENT)
			return ret;
		if (!ret)
			break;
	}

	ret = init_gz(member_len, member_ptr);
	if (ret < 0) {
		pr_err("Failed to inizialize zlib\n");
		return ret;
	}

	ret = untar(ctx, func);
	if (ret < 0) {
		pr_err("Failed to extract digests\n");
		return ret;
	}

	return end_gz();
}

int ima_parse_deb_packages_gz(loff_t size, void *buf, u16 data_algo, void *ctx,
			      callback_func func)
{
	char buff[1024], *buff_ptr = buff, *line_ptr;
	const char *algo_name = hash_algo_name[data_algo];
	const char *filename_str = "Filename";
	int ret, filename_str_len = strlen(filename_str);

	ret = init_gz(size, buf);
	if (ret < 0) {
		pr_err("Failed to initialize zlib\n");
		return ret;
	}

	for (;;) {
		ret = ima_getline_gz(sizeof(buff), buff, &buff_ptr,
				     &line_ptr, 0);
		if (ret < 0) {
			if (ret != -ENODATA)
				return ret;

			break;
		}

		if ((!strncasecmp(line_ptr, algo_name, strlen(algo_name)) ||
		    !strncmp(line_ptr, filename_str, filename_str_len)) &&
		    func) {
			ret = func(ctx, line_ptr);
			if (ret < 0) {
				end_gz();
				return ret;
			}
		}

		size -= ret;
	}

	return end_gz();
}

int ima_parse_deb_release(loff_t size, void *buf, u16 data_algo, void *ctx,
			  callback_func func)
{
	void *bufp = buf, *last_bufp = bufp;
	const char *algo_name = hash_algo_name[data_algo];
	const char *packages_gz_str = "Packages.gz";
	const char *packages_str = "Packages";
	int l_gz = strlen(packages_gz_str), l = strlen(packages_str);
	int ret, algo_found = 0;

	for (;;) {
		bufp = strchr(last_bufp, '\n');
		if (!bufp)
			break;

		*(char *)bufp = '\0';

		if (!strncasecmp(last_bufp, algo_name, strlen(algo_name))) {
			algo_found = 1;
			goto end;
		}

		if (algo_found && *(char *)last_bufp != ' ') {
			algo_found = 0;
			goto end;
		}

		if (!algo_found)
			goto end;

		if ((!strncmp(bufp - l, packages_str, l) ||
		    !strncmp(bufp - l_gz, packages_gz_str, l_gz)) && func) {
			ret = func(ctx, last_bufp);
			if (ret < 0)
				return ret;
		}
end:
		if (bufp == buf + size)
			break;

		last_bufp = bufp + 1;
	}

	return 0;
}
