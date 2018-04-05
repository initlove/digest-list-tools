/*
 * Copyright (C) 2018 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: gen_parser_metadata.c
 *      Generate parser metadata.
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "metadata.h"

void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <directory>: directory where the data is stored\n"
	       "\t-h: display help\n"
	       "\t-e <algorithm>: digest algorithm\n"
	       "\t-p <parser data file>: name of parser data file\n"
	       "\t-m <parser metadata file>: name of parser metadata file\n"
	       "\t-i <parser binary path>: path of the digest list parser\n"
	       "\t-s: sign digest list with gpg\n"
	       "\t-k <key name>: gpg key name\n"
	       "\t-w: overwrite parser data and signature\n"
	       "\t-o <binary metadata path>: binary path included as metadata\n"
	);
}

int main(int argc, char **argv)
{
	char *parser_data_filename = "parser_data";
	char *parser_metadata_filename = "parser_metadata";
	char parser_data_path[MAX_PATH_LENGTH];
	char parser_data_sig_path[MAX_PATH_LENGTH];
	char parser_metadata_path[MAX_PATH_LENGTH];
	char *binary_path = "/usr/bin/upload_digest_lists";
	char *outdir = "/etc/ima/digest_lists";
	int ret = 0, c, sign = 0;
	char *gpg_key_name = NULL, *binary_metadata_path = NULL;
	int overwrite = 0;
	struct stat st;

	while ((c = getopt(argc, argv, "hd:e:p:m:i:sk:wo:")) != -1) {
		switch (c) {
		case 'd':
			outdir = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return -EINVAL;
		case 'e':
			if (ima_hash_setup(optarg)) {
				printf("Unknown algorithm %s\n", optarg);
				return -EINVAL;
			}
			break;
		case 'p':
			parser_data_filename = optarg;
			break;
		case 'm':
			parser_metadata_filename = optarg;
			break;
		case 'i':
			binary_path = optarg;
			break;
		case 's':
			sign = 1;
			break;
		case 'k':
			gpg_key_name = optarg;
			break;
		case 'w':
			overwrite = 1;
			break;
		case 'o':
			binary_metadata_path = optarg;
			break;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	if (binary_path == NULL) {
		printf("Parser binary not specified\n");
		return -EINVAL;
	}

	if (binary_metadata_path == NULL)
		binary_metadata_path = binary_path;

	snprintf(parser_data_path, sizeof(parser_data_path), "%s/%s", outdir,
		 parser_data_filename);
	snprintf(parser_data_sig_path, sizeof(parser_data_sig_path),
		 "%s/%s.gpg", outdir, parser_data_filename);
	snprintf(parser_metadata_path, sizeof(parser_metadata_path), "%s/%s",
		 outdir, parser_metadata_filename);

	if (overwrite) {
		unlink(parser_data_path);
		unlink(parser_data_sig_path);
	}

	OpenSSL_add_all_digests();

	if (stat(parser_data_path, &st) < 0)
		write_parser_data(parser_data_path, binary_path);
	else
		pr_debug("Using %s, add -w option to overwrite parser data "
		         "and signature\n", parser_data_path);

	if (sign)
		sign_digest_list(parser_data_path, gpg_key_name);

	ret = creat(parser_metadata_path, 0600);
	if (ret < 0) {
		printf("Unable to write metadata file %s\n",
		       parser_metadata_path);
		goto out;
	}

	ret = truncate(parser_metadata_path, 0);
	if (ret < 0) {
		printf("Unable to truncate metadata file %s\n",
		       parser_metadata_path);
		goto out;
	}

	ret = write_metadata_header(parser_metadata_path);
	if (ret < 0)
		goto out;

	ret = write_parser_metadata(parser_data_path, parser_metadata_path,
				    binary_metadata_path);
out:
	EVP_cleanup();
	return ret;
}
