/*
 * Copyright (C) 2017,2018 Huawei Technologies Duesseldorf GmbH
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
#include "compact_list.h"
#include "rpm.h"
#include "deb.h"

static int write_digest_lists(char *outdir, char *metadata_filename,
			      int add_metadata, enum input_formats input_fmt,
			      char *input_path,
			      enum digest_data_sub_types output_fmt,
			      int is_mutable, int sign, char *gpg_key_name,
			      char *distro, char *repo_url)
{
	char metadata_path[MAX_PATH_LENGTH];
	int ret;

	snprintf(metadata_path, sizeof(metadata_path), "%s/%s", outdir,
		 metadata_filename);

	if (!add_metadata) {
		ret = creat(metadata_path, 0600);
		if (ret < 0) {
			printf("Unable to write metadata file %s\n",
			       metadata_path);
			return -EACCES;
		}

		ret = truncate(metadata_path, 0);
		if (ret < 0) {
			printf("Unable to truncate metadata file %s\n",
			       metadata_path);
			return -EACCES;
		}

		ret = write_metadata_header(metadata_path);
		if (ret < 0)
			return ret;
	}

	switch (input_fmt) {
	case INPUT_FMT_RPMDB:
		ret = digest_list_from_rpmdb(outdir, metadata_path, output_fmt,
					     sign, gpg_key_name);
		break;
	case INPUT_FMT_RPMPKG:
		ret = digest_lists_from_rpmpkg(outdir, metadata_path,
					       input_path, output_fmt,
					       sign, gpg_key_name);
		break;
	case INPUT_FMT_DIGEST_LIST_ASCII:
		ret = digest_list_from_ascii(outdir, metadata_path, input_path,
					     output_fmt, is_mutable,
					     sign, gpg_key_name);
		break;
	case INPUT_FMT_DEBDB:
		ret = digest_list_from_deb_mirror(outdir, metadata_path,
						  output_fmt, distro, repo_url);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static void usage(char *progname)
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
	       "\t-e <algorithm>: digest algorithm\n"
	       "\t-s: sign digest list with gpg\n"
	       "\t-k <key name>: gpg key name\n"
	       "\t-j <distro name>: distribution name\n"
	       "\t-u <repo url>: URL of the repository\n");
}

int main(int argc, char **argv)
{
	int add_metadata = 0, is_mutable = 0;
	char *input_path = NULL, *metadata_filename = "metadata";
	char *outdir = NULL;
	enum input_formats input_fmt = INPUT_FMT_RPMDB;
	enum digest_data_sub_types output_fmt = DATA_SUB_TYPE_COMPACT_LIST;
	char *distro = "ubuntu", *repo_url = UBUNTU_REPO_URL;
	int c, ret, sign = 0;
	char *gpg_key_name = NULL;

	while ((c = getopt(argc, argv, "ad:f:i:m:o:hwe:sk:j:u:")) != -1) {
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
			} else if (strcmp(optarg, "debdb") == 0) {
				input_fmt = INPUT_FMT_DEBDB;
			} else {
				printf("Unknown input format %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'h':
			usage(argv[0]);
			return -EINVAL;
		case 'i':
			input_path = optarg;
			break;
		case 'm':
			metadata_filename = optarg;
			break;
		case 'o':
			if (strcmp(optarg, "compact") == 0) {
				output_fmt = DATA_SUB_TYPE_COMPACT_LIST;
			} else if (strcmp(optarg, "rpm") == 0) {
				output_fmt = DATA_SUB_TYPE_RPM;
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
		case 's':
			sign = 1;
			break;
		case 'k':
			gpg_key_name = optarg;
			break;
		case 'j':
			distro = optarg;
			break;
		case 'r':
			repo_url = optarg;
			break;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	if (input_fmt != INPUT_FMT_RPMDB  && input_fmt != INPUT_FMT_DEBDB &&
	    input_path == NULL) {
		printf("Input file not specified\n");
		return -EINVAL;
	}

	if (input_fmt == INPUT_FMT_RPMDB && input_path != NULL) {
		printf("Input file format not specified\n");
		return -EINVAL;
	}

	if (input_fmt == INPUT_FMT_DIGEST_LIST_ASCII &&
	    output_fmt == DATA_SUB_TYPE_RPM) {
		printf("Invalid output format\n");
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
				 input_fmt, input_path, output_fmt,
				 is_mutable, sign, gpg_key_name, distro,
				 repo_url);
	EVP_cleanup();
	return ret;
}
