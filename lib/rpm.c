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
 * File: rpm.c
 *      Writes RPM digest lists.
 */

#include <stdio.h>
#include <fcntl.h>

#include "rpm.h"

static int algo_mapping[HASH_ALGO__LAST] = {
	[PGPHASHALGO_SHA1] = HASH_ALGO_SHA1,
	[PGPHASHALGO_SHA256] = HASH_ALGO_SHA256,
};

void get_rpm_filename(Header rpm, char *outdir, char *output_filename,
		      enum digest_data_types output_fmt)
{
	char *pkg_name, *pkg_version, *pkg_release, *pkg_arch;
	char *prefix = (output_fmt == DATA_TYPE_RPM) ? "rpm" : "compact";

	headerGetEntry(rpm, RPMTAG_NAME, NULL, (void **)&pkg_name, NULL);
	headerGetEntry(rpm, RPMTAG_VERSION, NULL, (void **)&pkg_version, NULL);
	headerGetEntry(rpm, RPMTAG_RELEASE, NULL, (void **)&pkg_release, NULL);
	headerGetEntry(rpm, RPMTAG_ARCH, NULL, (void **)&pkg_arch, NULL);

	snprintf(output_filename, MAX_FILENAME_LENGTH, "%s/%s-%s-%s-%s.%s",
		 outdir, prefix, pkg_name, pkg_version, pkg_release, pkg_arch);
}

int check_rpm_digest_algo(Header rpm, char *output_filename)
{
	u32 *rpm_digestalgo;
	rpm_tagtype_t data_type;
	rpm_count_t data_count;
	int ret;

	ret = headerGetEntry(rpm, RPMTAG_FILEDIGESTALGO, &data_type,
			     (void **)&rpm_digestalgo, &data_count);
	if (ret < 0) {
		printf("%s: unable to retrieve digest algorithm\n",
		       output_filename);
		return -EINVAL;
	}

	if (strstr(output_filename, "gpg-pubkey") != NULL)
		return -ENOENT;

	if (algo_mapping[*rpm_digestalgo] != ima_hash_algo) {
		printf("%s: digest algorithm mismatch, expected: %s, "
		       "current: %s\n", output_filename,
		       hash_algo_name[ima_hash_algo],
		       hash_algo_name[algo_mapping[*rpm_digestalgo]]);
		return -EINVAL;
	}

	return 0;
}

void get_rpm_header_signature(Header rpm, u8 **signature,
			      rpm_count_t *signature_len)
{
	headerGetEntry(rpm, RPMTAG_RSAHEADER, NULL, (void **)signature,
		       signature_len);
}

int write_rpm_header(Header rpm, char *outdir, char *output_filename)
{
	char **data;
	rpm_count_t data_size;
	int ret, fd;

	get_rpm_filename(rpm, outdir, output_filename, DATA_TYPE_RPM);

	ret = check_rpm_digest_algo(rpm, output_filename);
	if (ret < 0)
		return ret;

	headerGetEntry(rpm, RPMTAG_HEADERIMMUTABLE, NULL,
		       (void **)&data, &data_size);

	fd = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -EACCES;

	write(fd, rpm_header_magic, sizeof(rpm_header_magic));
	write(fd, data, data_size);
	close(fd);
	return 0;
}
