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

#include "kernel_ima.h"

/* rpmlegacy.h */
int headerGetEntry(Header h, rpm_tag_t tag, rpm_tagtype_t *type,
		   rpm_data_t *p, rpm_count_t *c);
void get_rpm_filename(Header rpm, char *outdir, char *output_filename,
		      enum digest_data_types output_fmt);
int check_rpm_digest_algo(Header rpm, char *output_filename);
void get_rpm_header_signature(Header rpm, u8 **signature,
			      rpm_count_t *signature_len);
int write_rpm_header(Header rpm, char *outdir, char *output_filename);

#endif /* _RPM_H */
