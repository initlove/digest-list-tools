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
 * File: metadata.h
 *      Header of metadata.c.
 */

#ifndef _METADATA_H
#define _METADATA_H

#include "compact_list.h"
#include "rpm.h"
#include "lib.h"

enum input_formats { INPUT_FMT_RPMDB, INPUT_FMT_RPMPKG,
		     INPUT_FMT_DIGEST_LIST_ASCII, INPUT_FMT__LAST };

int write_digests_and_metadata(Header hdr, char *outdir,
			       char *metadata_filename,
			       enum input_formats input_fmt,
			       char *input_filename,
			       enum digest_data_types output_fmt,
			       int is_mutable);

#endif /*_METADATA_H*/
