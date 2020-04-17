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
 * File: cap.c
 *      Produce/parse security.capability.
 */

#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <sys/capability.h>
#include <linux/capability.h>

#ifdef __BIG_ENDIAN__
#define FIXUP_32BITS(x) bswap_32(x)
#else
#define FIXUP_32BITS(x) (x)
#endif

#define NUMBER_OF_CAP_SETS      3   /* effective, inheritable, permitted */
#define __CAP_BLKS   (_LINUX_CAPABILITY_U32S)
#define CAP_SET_SIZE (__CAP_BLKS * sizeof(__u32))

struct _cap_struct {
	struct __user_cap_header_struct head;
	union {
		struct __user_cap_data_struct set;
		__u32 flat[NUMBER_OF_CAP_SETS];
	} u[_LINUX_CAPABILITY_U32S];
};

cap_t _fcaps_load(struct vfs_cap_data *rawvfscap, cap_t result, int bytes)
{
	__u32 magic_etc;
	unsigned tocopy, i;

	magic_etc = FIXUP_32BITS(rawvfscap->magic_etc);
	switch (magic_etc & VFS_CAP_REVISION_MASK) {
	case VFS_CAP_REVISION_1:
		tocopy = VFS_CAP_U32_1;
		bytes -= XATTR_CAPS_SZ_1;
		break;

	case VFS_CAP_REVISION_2:
		tocopy = VFS_CAP_U32_2;
		bytes -= XATTR_CAPS_SZ_2;
		break;

	default:
		cap_free(result);
		result = NULL;
		return result;
	}

	/*
	* Verify that we loaded exactly the right number of bytes
	*/
	if (bytes != 0) {
		cap_free(result);
		result = NULL;
		return result;
	}

	for (i=0; i < tocopy; i++) {
		result->u[i].flat[CAP_INHERITABLE] =
				FIXUP_32BITS(rawvfscap->data[i].inheritable);
		result->u[i].flat[CAP_PERMITTED] =
				FIXUP_32BITS(rawvfscap->data[i].permitted);
		if (magic_etc & VFS_CAP_FLAGS_EFFECTIVE) {
			result->u[i].flat[CAP_EFFECTIVE] =
					result->u[i].flat[CAP_INHERITABLE] |
					result->u[i].flat[CAP_PERMITTED];
		}
	}

	while (i < __CAP_BLKS) {
		result->u[i].flat[CAP_INHERITABLE] =
			result->u[i].flat[CAP_PERMITTED] =
			result->u[i].flat[CAP_EFFECTIVE] = 0;
		i++;
	}

	return result;
}

int _fcaps_save(struct vfs_cap_data *rawvfscap, cap_t cap_d, int *bytes_p)
{
	__u32 eff_not_zero, magic;
	unsigned tocopy, i;

	switch (cap_d->head.version) {
	case _LINUX_CAPABILITY_VERSION_1:
		magic = VFS_CAP_REVISION_1;
		tocopy = VFS_CAP_U32_1;
		*bytes_p = XATTR_CAPS_SZ_1;
		break;

	case _LINUX_CAPABILITY_VERSION_2:
		magic = VFS_CAP_REVISION_2;
		tocopy = VFS_CAP_U32_2;
		*bytes_p = XATTR_CAPS_SZ_2;
		break;

	case _LINUX_CAPABILITY_VERSION_3:
		magic = VFS_CAP_REVISION_2;
		tocopy = VFS_CAP_U32_2;
		*bytes_p = XATTR_CAPS_SZ_2;
		break;

	default:
		errno = EINVAL;
		return -1;
	}

	for (eff_not_zero = 0, i = 0; i < tocopy; i++) {
		eff_not_zero |= cap_d->u[i].flat[CAP_EFFECTIVE];
	}

	while (i < __CAP_BLKS) {
		if ((cap_d->u[i].flat[CAP_EFFECTIVE] ||
		    cap_d->u[i].flat[CAP_INHERITABLE] ||
		    cap_d->u[i].flat[CAP_PERMITTED])) {
			/*
			 * System does not support these capabilities
			 */
			errno = EINVAL;
			return -1;
		}
		i++;
	}

	for (i=0; i < tocopy; i++) {
		rawvfscap->data[i].permitted =
			FIXUP_32BITS(cap_d->u[i].flat[CAP_PERMITTED]);
		rawvfscap->data[i].inheritable =
			FIXUP_32BITS(cap_d->u[i].flat[CAP_INHERITABLE]);

		if (eff_not_zero
		    && ((~(cap_d->u[i].flat[CAP_EFFECTIVE])) &
		    (cap_d->u[i].flat[CAP_PERMITTED] |
		    cap_d->u[i].flat[CAP_INHERITABLE]))) {
			errno = EINVAL;
			return -1;
		}
	}

	if (eff_not_zero == 0) {
		rawvfscap->magic_etc = FIXUP_32BITS(magic);
	} else {
		rawvfscap->magic_etc =
			FIXUP_32BITS(magic|VFS_CAP_FLAGS_EFFECTIVE);
	}

	return 0;      /* success */
}
