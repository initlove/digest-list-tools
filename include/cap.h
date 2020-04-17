/*
 * Copyright (C) 2017-2020 Huawei Technologies Duesseldorf GmbH
 * Copyright (c) 1997,2007,2016 Andrew G Morgan <morgan@kernel.org>
 *
 * Authors:
 *     Andrew G Morgan <morgan@kernel.org>
 *     Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: cap.h
 *      Header of cap.c.
 */

#ifndef _CAP_H
#define _CAP_H

cap_t _fcaps_load(struct vfs_cap_data *rawvfscap, cap_t result, int bytes);
int _fcaps_save(struct vfs_cap_data *rawvfscap, cap_t cap_d, int *bytes_p);

#endif /*_CAP_H*/
