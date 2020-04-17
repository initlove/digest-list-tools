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
 * File: selinux.c
 *      Library to get SELinux labels.
 */

#include <errno.h>

#include <selinux/label.h>
#include <selinux/restorecon.h>

#include "selinux.h"

static struct selabel_handle *h;

int selinux_init_setup(void)
{
	int rc = 0;

	h = selabel_open(SELABEL_CTX_FILE, NULL, 0);
	if (!h) {
		pr_err("Cannot initialize libselinux\n");
		return -EPERM;
	}

	selinux_restorecon_set_sehandle(h);

	return rc;
}

void selinux_end_setup(void)
{
	if (h) {
		selabel_close(h);
		h = NULL;
	}
}

int get_selinux_label(char *path, char *alt_root, char **label, mode_t mode)
{
	int offset = alt_root ? strlen(alt_root) : 0;
	int ret;

	if (!h) {
		ret = selinux_init_setup();
		if (ret < 0) {
			*label = NULL;
			return 0;
		}
	}

	return selabel_lookup_raw(h, label, path + offset, mode);
}
