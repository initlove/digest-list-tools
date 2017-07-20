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
 * File: compact_list.h
 *      Header of compact_list.c.
 */

#ifndef _COMPACT_LIST_H
#define _COMPACT_LIST_H

#include "kernel_ima.h"
#include "rpm.h"

int compact_list_from_rpm(Header rpm, char *outdir, char *output_filename);
int compact_list_from_digest_list_ascii(char *input_filename, char *outdir,
					char *output_filename, int is_mutable);

#endif /*_COMPACT_LIST_H*/
