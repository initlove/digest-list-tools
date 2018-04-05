/*
 * Copyright (C) 2018 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: deb.h
 *      Header of deb.c.
 */

#ifndef _DEB_H
#define _DEB_H

#include "kernel_ima.h"
#include "metadata.h"

#define UBUNTU_REPO_URL "http://archive.ubuntu.com/ubuntu"
#define DPKG_QUERY_FMT "'${Package} ${Version} ${Architecture}\n'"
#define DPKG_QUERY_CMD "dpkg-query -W -f " DPKG_QUERY_FMT

int ima_parse_deb_package(loff_t size, void *buf, u16 data_algo, void *ctx,
			  callback_func func);
int ima_parse_deb_packages_gz(loff_t size, void *buf, u16 data_algo, void *ctx,
			      callback_func func);
int ima_parse_deb_release(loff_t size, void *buf, u16 data_algo, void *ctx,
			  callback_func func);

int digest_list_from_deb_mirror(char *outdir, char *metadata_path,
				enum digest_data_sub_types output_fmt,
				char *distro, char *repo_url);

#endif /* _DEB_H */
