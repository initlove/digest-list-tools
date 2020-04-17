/*
 * Copyright (C) 2019-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_list.h
 *      Header of ima_list.c.
 */

#ifndef _IMA_LIST_H
#define _IMA_LIST_H

int ima_copy_boot_aggregate(int fd);
int ima_generate_entry(int dirfd, int fd, char *digest_list_dir,
		       char *digest_list_filename);

#endif /*_IMA_LIST_H*/
