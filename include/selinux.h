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
 * File: selinux.h
 *      Header of selinux.c.
 */

#ifndef _SELINUX_H
#define _SELINUX_H

#include "kernel_lib.h"

int selinux_init_setup(void);
void selinux_end_setup(void);
int get_selinux_label(char *path, char *alt_root, char **label, mode_t mode);

#endif /*SELINUX*/
