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
 * File: rpm.h
 *      Header of rpm.c.
 */

#ifndef _RPM_H
#define _RPM_H

#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>

#include "metadata.h"
#include "compact_list.h"

void get_rpm_path(Header rpm, char *outdir, char *output_path,
		  enum digest_data_sub_types output_fmt);

int ima_parse_rpm(loff_t size, void *buf, u16 data_algo, void *ctx,
		  callback_func func);

int digest_list_from_rpmdb(char *outdir, char *metadata_path,
			   enum digest_data_sub_types output_fmt,
			   int sign, char *gpg_key_name);
int digest_lists_from_rpmpkg(char *outdir, char *metadata_path,
			     char *package_path,
			     enum digest_data_sub_types output_fmt,
			     int sign, char *gpg_key_name);
#endif /* _RPM_H */
