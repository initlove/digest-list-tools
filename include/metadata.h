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

#include "kernel_ima.h"
#include "pgp.h"

enum input_formats { INPUT_FMT_RPMDB, INPUT_FMT_RPMPKG,
		     INPUT_FMT_DIGEST_LIST_ASCII, INPUT_FMT_DEBDB,
		     INPUT_FMT__LAST };

int write_digests_and_metadata(char *outdir, char *metadata_path,
			       char *digest_list_path,
			       enum digest_data_sub_types output_fmt, int sign);
int write_parser_data(char *parser_data_path, char *binary_path);
int write_parser_metadata(char *parser_data_path, char *parser_metadata_path,
			  char *binary_path);
int write_metadata_header(char *metadata_path);
int write_pgp_key(char *metadata_path, char *pgp_key_path);

#endif /*_METADATA_H*/
