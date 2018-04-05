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

void get_rpm_path(Header rpm, char *outdir, char *output_path,
		  enum digest_data_sub_types output_fmt)
{
	char *prefix = (output_fmt == DATA_SUB_TYPE_RPM) ? "rpm" : "compact";
	rpmtd name = rpmtdNew(), version = rpmtdNew();
	rpmtd release = rpmtdNew(), arch = rpmtdNew();

	headerGet(rpm, RPMTAG_NAME, name, 0);
	headerGet(rpm, RPMTAG_VERSION, version, 0);
	headerGet(rpm, RPMTAG_RELEASE, release, 0);
	headerGet(rpm, RPMTAG_ARCH, arch, 0);

	snprintf(output_path, MAX_PATH_LENGTH, "%s/%s-%s-%s-%s.%s",
		 outdir, prefix, rpmtdGetString(name), rpmtdGetString(version),
		 rpmtdGetString(release), rpmtdGetString(arch));

	rpmtdReset(name);
	rpmtdReset(version);
	rpmtdReset(release);
	rpmtdReset(arch);
}

static int write_rpm_header_signature(Header rpm, char *digest_list_path)
{
	char rpm_sig_path[MAX_PATH_LENGTH];
	rpmtd signature = rpmtdNew();
	int ret, fd;

	snprintf(rpm_sig_path, sizeof(rpm_sig_path), "%s.sig",
		 digest_list_path);

	fd = open(rpm_sig_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -EACCES;

	headerGet(rpm, RPMTAG_RSAHEADER, signature, 0);
	ret = write_check(fd, signature->data, signature->count);
	rpmtdReset(signature);

	close(fd);
	return ret;
}

static int write_rpm_header(Header rpm, char *outdir, char *output_path)
{
	rpmtd immutable = rpmtdNew();
	ssize_t ret;
	int fd;

	get_rpm_path(rpm, outdir, output_path, DATA_SUB_TYPE_RPM);

	if (strstr(output_path, "gpg-pubkey") != NULL)
		return -ENOENT;

	fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -EACCES;

	ret = write_check(fd, rpm_header_magic, sizeof(rpm_header_magic));
	if (ret < 0)
		goto out;

	headerGet(rpm, RPMTAG_HEADERIMMUTABLE, immutable, 0);
	ret = write_check(fd, immutable->data, immutable->count);
	rpmtdReset(immutable);
out:
	close(fd);
	return ret;
}

static int write_digest_list_from_rpm(Header hdr, char *outdir,
				      enum digest_data_sub_types output_fmt,
				      char *digest_list_path, int sign,
				      char *gpg_key_name)
{
	int ret;

	if (output_fmt == DATA_SUB_TYPE_COMPACT_LIST) {
		ret = compact_list_from_rpm(hdr, outdir, digest_list_path);
		if (!ret && sign)
			ret = sign_digest_list(digest_list_path, gpg_key_name);
	} else if (output_fmt == DATA_SUB_TYPE_RPM) {
		ret = write_rpm_header(hdr, outdir, digest_list_path);
		if (!ret)
			ret = write_rpm_header_signature(hdr, digest_list_path);
	} else {
		ret = -EINVAL;
	}

	return ret;
}

int digest_list_from_rpmdb(char *outdir, char *metadata_path,
			   enum digest_data_sub_types output_fmt,
			   int sign, char *gpg_key_name)
{
	char digest_list_path[MAX_PATH_LENGTH];
	rpmts ts = NULL;
	Header hdr;
	rpmdbMatchIterator mi;
	int ret;

	ts = rpmtsCreate();
	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		exit(1);
	}

	mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
	while ((hdr = rpmdbNextIterator(mi)) != NULL) {
		hdr = headerLink(hdr);

		ret = write_digest_list_from_rpm(hdr, outdir, output_fmt,
						 digest_list_path, sign,
						 gpg_key_name);
		if (ret < 0 && ret != -ENOENT) {
			pr_err("Failed to write %s, ret: %d\n",
			       digest_list_path, ret);
				goto end;
		} else if (ret == -ENOENT) {
			ret = 0;
			goto end;
		}

		ret = write_digests_and_metadata(outdir, metadata_path,
						 digest_list_path,
						 output_fmt, sign);
end:
		headerFree(hdr);

		if (ret < 0)
			break;
	}

	rpmdbFreeIterator(mi);
	rpmtsFree(ts);
	return ret;
}

int digest_lists_from_rpmpkg(char *outdir, char *metadata_path,
			     char *package_path,
			     enum digest_data_sub_types output_fmt,
			     int sign, char *gpg_key_name)
{
	char digest_list_path[MAX_PATH_LENGTH];
	Header hdr;
	rpmts ts = NULL;
	FD_t fd;
	int ret;
	rpmVSFlags vsflags = 0;

	ts = rpmtsCreate();
	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		exit(1);
	}

	vsflags |= _RPMVSF_NODIGESTS;
	vsflags |= _RPMVSF_NOSIGNATURES;
	rpmtsSetVSFlags(ts, vsflags);

	fd = Fopen(package_path, "r.ufdio");
	if ((!fd) || Ferror(fd)) {
		rpmlog(RPMLOG_NOTICE, "Failed to open package file (%s)\n",
		       Fstrerror(fd));
		if (fd)
			Fclose(fd);

		return -EINVAL;
	}

	ret = rpmReadPackageFile(ts, fd, package_path, &hdr);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Could not read package file\n");
		goto out;
	}

	ret = write_digest_list_from_rpm(hdr, outdir, output_fmt,
					 digest_list_path, sign,
				         gpg_key_name);
	if (ret < 0 && ret != -ENOENT) {
		pr_err("Failed to write %s, ret: %d\n", digest_list_path, ret);
		goto out;
	} else if (ret == -ENOENT) {
		ret = 0;
		goto out;
	}

	ret = write_digests_and_metadata(outdir, metadata_path,
					 digest_list_path, output_fmt, sign);
out:
	Fclose(fd);
	rpmtsFree(ts);
	return ret;
}
