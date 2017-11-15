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
 * File: gen_digest_lists.c
 *      Handles command line options and retrieve digests.
 */

#include <stdio.h>
#include <fcntl.h>

#include "metadata.h"

static int digest_list_from_rpmdb(char *outdir, char *metadata_filename,
				  enum digest_data_types output_fmt)
{
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

		ret = write_digests_and_metadata(hdr, outdir, metadata_filename,
						 INPUT_FMT_RPMDB, NULL,
						 output_fmt, 0);
		if (ret < 0)
			break;

		headerFree(hdr);
	}

	rpmdbFreeIterator(mi);
	rpmtsFree(ts);
	return ret;
}

int digest_lists_from_rpmpkg(char *outdir, char *metadata_filename,
			     char *package_path,
			     enum digest_data_types output_fmt)
{
	Header hdr;
	rpmts ts = NULL;
	FD_t fd;
	int ret;

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
			Fclose(fd);
			exit(1);
	}

	Fclose(fd);
	ret = write_digests_and_metadata(hdr, outdir, metadata_filename,
					 INPUT_FMT_RPMPKG, NULL, output_fmt, 0);
	rpmtsFree(ts);
	return ret;
}

int write_digest_lists(char *outdir, char *metadata_filename,
		       int add_metadata, enum input_formats input_fmt,
		       char *input_filename, enum digest_data_types output_fmt,
		       int is_mutable)
{
	char filename[MAX_FILENAME_LENGTH];
	int ret = 0, fd;

	snprintf(filename, sizeof(filename), "%s/%s", outdir,
		 metadata_filename);

	fd = open(filename, O_WRONLY | O_CREAT, 0600);
	if (fd < 0) {
		printf("Unable to write metadata file %s\n", filename);
		return -EACCES;
	}

	if (!add_metadata)
		ftruncate(fd, 0);

	switch (input_fmt) {
	case INPUT_FMT_RPMDB:
		ret = digest_list_from_rpmdb(outdir, filename, output_fmt);
		break;
	case INPUT_FMT_RPMPKG:
		ret = digest_lists_from_rpmpkg(outdir, filename, input_filename,
					       output_fmt);
		break;
	case INPUT_FMT_DIGEST_LIST_ASCII:
		ret = write_digests_and_metadata(NULL, outdir, filename,
						 INPUT_FMT_DIGEST_LIST_ASCII,
						 input_filename, output_fmt,
						 is_mutable);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-a: append metadata to an existing file\n"
	       "\t-d <directory>: directory where digest lists and metadata "
	       "are stored\n"
	       "\t-f <input format>: format of the input where digests "
	       "are taken from\n"
	       "\t\trpmdb: RPM database\n"
	       "\t\trpmpkg: RPM package\n"
	       "\t\tascii: file containing ASCII digests for each line\n"
	       "\t-h: display help\n"
	       "\t-i <path>: path of the file where digests are taken from\n"
	       "\t-m <file name>: metadata file name\n"
	       "\t-o <output format>: output format of the digest list\n"
	       "\t\tcompact: compact digest list\n"
	       "\t\trpm: RPM package header\n"
	       "\t-w: files are mutable\n"
	       "\t-e <algorithm>: digest algorithm\n");
}

int main(int argc, char **argv)
{
	int add_metadata = 0, is_mutable = 0;
	char *input_filename = NULL, *metadata_filename = "metadata";
	char *outdir = NULL;
	enum input_formats input_fmt = INPUT_FMT_RPMDB;
	enum digest_data_types output_fmt = DATA_TYPE_COMPACT_LIST;
	int c, ret;

	while ((c = getopt(argc, argv, "ad:f:i:m:o:hwe:")) != -1) {
		switch (c) {
		case 'a':
			add_metadata = 1;
			break;
		case 'd':
			outdir = optarg;
			break;
		case 'f':
			if (strcmp(optarg, "rpmdb") == 0) {
				input_fmt = INPUT_FMT_RPMDB;
			} else if (strcmp(optarg, "rpmpkg") == 0) {
				input_fmt = INPUT_FMT_RPMPKG;
			} else if (strcmp(optarg, "ascii") == 0) {
				input_fmt = INPUT_FMT_DIGEST_LIST_ASCII;
			} else {
				printf("Unknown input format %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'h':
			usage(argv[0]);
			return -EINVAL;
		case 'i':
			input_filename = optarg;
			break;
		case 'm':
			metadata_filename = optarg;
			break;
		case 'o':
			if (strcmp(optarg, "compact") == 0) {
				output_fmt = DATA_TYPE_COMPACT_LIST;
			} else if (strcmp(optarg, "rpm") == 0) {
				output_fmt = DATA_TYPE_RPM;
			} else {
				printf("Unknown output format %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'w':
			is_mutable = 1;
			break;
		case 'e':
			if (ima_hash_setup(optarg)) {
				printf("Unknown algorithm %s\n", optarg);
				return -EINVAL;
			}
			break;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	if (input_fmt != INPUT_FMT_RPMDB && input_filename == NULL) {
		printf("Input file not specified\n");
		return -EINVAL;
	}

	if (input_fmt == INPUT_FMT_RPMDB && input_filename != NULL) {
		printf("Input file format not specified\n");
		return -EINVAL;
	}

	if (outdir == NULL) {
		printf("Output directory not specified\n");
		return -EINVAL;
	}

	if (outdir[0] != '/') {
		printf("Absolute path of output directory must be specified\n");
		return -EINVAL;
	}

	OpenSSL_add_all_digests();

	ret = write_digest_lists(outdir, metadata_filename, add_metadata,
				 input_fmt, input_filename, output_fmt,
				 is_mutable);
	EVP_cleanup();
	return ret;
}
