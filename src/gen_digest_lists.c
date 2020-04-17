/*
 * Copyright (C) 2011 Nokia Corporation
 * Copyright (C) 2011,2012,2013 Intel Corporation
 * Copyright (C) 2013,2014 Samsung Electronics
 * Copyright (C) 2017-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 * Roberto Sassu <roberto.sassu@huawei.com>
 * Dmitry Kasatkin <dmitry.kasatkin@nokia.com>
 *                 <dmitry.kasatkin@intel.com>
 *                 <d.kasatkin@samsung.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: gen_digest_lists.c
 *      Generate digest lists.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <termios.h>
#include <sys/mman.h>

#include "compact_list.h"
#include "crypto.h"

#define DEFAULT_DIR "/etc/ima/digest_lists"


enum input_formats { INPUT_FMT_RPMDB, INPUT_FMT_RPMPKG, INPUT_FMT__LAST };
enum dir_ops { OP_ADD, OP_APPEND, OP_REMOVE, OP_SIGN, OP__LAST };

/* from evmctl.c */
static char *get_password(char *keypass, int keypass_len)
{
	struct termios flags, tmp_flags;
	char *pwd;

	tcgetattr(fileno(stdin), &flags);
	tmp_flags = flags;
	tmp_flags.c_lflag &= ~ECHO;
	tmp_flags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &tmp_flags) != 0) {
		perror("tcsetattr");
		return NULL;
	}

	printf("PEM password: ");
	pwd = fgets(keypass, keypass_len, stdin);

	/* restore terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &flags) != 0) {
		perror("tcsetattr");
		return NULL;
	}

	return pwd;
}

static int process_dir(int dirfd, enum dir_ops op, enum compact_types type,
		       int *pos)
{
	struct dirent **digest_lists;
	char new_filename[NAME_MAX + 1], target[NAME_MAX +1];
	char *cur_filename, *symlink_filename = NULL;
	int ret = 0, i, n, index;

	n = scandirat(dirfd, ".", &digest_lists, filter_parser_list_symlink,
		      NULL);
	if (n != -1) {
		if (n == 1) {
			ret = readlinkat(dirfd, digest_lists[0]->d_name, target,
					 sizeof(target) - 1);
			if (ret < 0) {
				printf("Cannot read symlink %s\n",
				       digest_lists[0]->d_name);
				goto out;
			}

			target[ret] = '\0';

			symlink_filename = strdup(digest_lists[0]->d_name);
			if (!symlink_filename)
				return -ENOMEM;

			free(digest_lists[0]);
		}

		free(digest_lists);
	}

	n = scandirat(dirfd, ".", &digest_lists, filter[type],
		      compare_lists);
	if (n == -1) {
		printf("Unable to access digest lists\n");
		return -EACCES;
	}

	if (op == OP_APPEND) {
		*pos = n;
		goto out;
	}

	for (i = 0; i < n; i++) {
		index = (op == OP_ADD) ? n - 1 - i : i;
		cur_filename = digest_lists[index]->d_name;

		if (op == OP_REMOVE && (*pos == -1 || index == *pos)) {
			unlinkat(dirfd, cur_filename, 0);
			if (symlink_filename && !strcmp(cur_filename, target))
				unlinkat(dirfd, symlink_filename, 0);
			continue;
		}

		if (i < *pos)
			continue;

		snprintf(new_filename, sizeof(new_filename), "%d%s",
			 (op == OP_ADD) ? index + 1 : index - 1,
			 strchr(cur_filename, '-'));
		renameat(dirfd, cur_filename, dirfd, new_filename);

		if (symlink_filename && !strcmp(cur_filename, target)) {
			unlinkat(dirfd, symlink_filename, 0);
			ret = symlinkat(new_filename, dirfd, symlink_filename);
			if (ret < 0)
				printf("Cannot create symbolic link\n");
		}
	}
out:
	for (i = 0; i < n; i++)
		free(digest_lists[i]);

	free(digest_lists);
	free(symlink_filename);

	return ret;
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <directory>: directory containing digest lists\n"
	       "\t-f <format>: format of the input file, "
	             "syntax: <generator ID>+<generator func>\n"
	       "\t-i <path>: path of the input file\n"
	       "\t-o <operation>: operation to do\n"
	       "\t\t-add: insert a new digest list at the position specified\n"
	       "\t\t-append: add a new digest list after the existing ones\n"
	       "\t\t-remove: remove a digest list at the position specified\n"
	       "\t\t-sign: sign a digest list\n"
	       "\t-p <position>: position in the directory to add/remove\n"
	       "\t-t <compact id>: type of compact list to generate\n"
	       "\t-T: generate a TLV compact list\n"
	       "\t-m <modifiers>: compact list modifiers separated by comma\n"
	       "\t-a <algorithm>: digest list hash algorithm\n"
	       "\t-I <algo>: IMA hash algorithm\n"
	       "\t-s: sign generated digest lists\n"
	       "\t-k <key>: key to sign\n"
	       "\t-w [<key password>]: key password or prompt\n"
	       "\t-A <alt root>: alternative root for SELinux labeling\n"
	       "\t-h: display help\n");
}

int main(int argc, char **argv)
{
	char *cur_dir = DEFAULT_DIR, *input_fmt = NULL, *alt_root = NULL;
	char *modifiers_opt, *modifiers_ptr, *modifiers_str;
	char keypass[64], *keypass_ptr = keypass, *key_path = NULL;
	enum dir_ops op = OP__LAST;
	enum compact_types type = COMPACT__LAST;
	enum hash_algo algo = HASH_ALGO_SHA256;
	enum hash_algo ima_algo = HASH_ALGO_SHA256;
	LIST_HEAD(generator_lib_head);
	LIST_HEAD(head_in);
	LIST_HEAD(head_out);
	struct lib *generator;
	bool tlv = false;
	int ret = -EINVAL, c, i, dirfd, sign = 0, pos = -1, modifiers = 0;

	while ((c = getopt(argc, argv, "d:f:i:o:p:t:Tm:a:I:sk:w:A:h")) != -1) {
		switch (c) {
		case 'd':
			cur_dir = optarg;
			break;
		case 'f':
			input_fmt = optarg;
			break;
		case 'i':
			if (add_path_struct(optarg, NULL, &head_in) < 0)
				goto out;
			break;
		case 'o':
			if (strcmp(optarg, "add") == 0) {
				op = OP_ADD;
			} else if (strcmp(optarg, "append") == 0) {
				op = OP_APPEND;
			} else if (strcmp(optarg, "remove") == 0) {
				op = OP_REMOVE;
			} else if (strcmp(optarg, "sign") == 0) {
				op = OP_SIGN;
				sign = 1;
			} else {
				printf("Invalid operation %s\n", optarg);
				goto out;
			}
			break;
		case 'p':
			pos = atoi(optarg);
			break;
		case 't':
			for (i = 0; i < COMPACT__LAST; i++)
				if (!strcmp(optarg, compact_types_str[i]))
					break;
			if (i == COMPACT__LAST) {
				printf("Unknown compact type %s\n", optarg);
				goto out;
			}
			type = i;
			break;
		case 'T':
			tlv = true;
			break;
		case 'm':
			modifiers_ptr = modifiers_opt = strdup(optarg);
			while ((modifiers_str = strsep(&modifiers_ptr, ","))) {
				for (i = 0; i < COMPACT_MOD__LAST; i++) {
					if (!strcmp(modifiers_str,
						    compact_modifiers_str[i])) {
						modifiers |= (1 << i);
						break;
					}
				}
			}
			free(modifiers_opt);
			break;
		case 'a':
		case 'I':
			for (i = 0; i < HASH_ALGO__LAST; i++)
				if (!strcmp(optarg, hash_algo_name[i]))
					break;
			if (i == HASH_ALGO__LAST) {
				printf("Unknown hash algorithm %s\n", optarg);
				goto out;
			}
			if (c == 'I')
				ima_algo = i;
			else
				algo = i;
			break;
		case 's':
			sign = 1;
			break;
		case 'k':
			key_path = optarg;
			break;
		case 'w':
			if (optarg)
				keypass_ptr = optarg;
			else
				keypass_ptr = get_password(keypass,
							   sizeof(keypass));
			break;
		case 'A':
			alt_root = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return -EINVAL;
		default:
			printf("Unknown option %c\n", optopt);
			return -EINVAL;
		}
	}

	ret = -EINVAL;

	if (op == OP__LAST) {
		printf("Operation not specified\n");
		goto out;
	}

	if ((op != OP_SIGN || list_empty(&head_in)) && type == COMPACT__LAST) {
		printf("Compact type not specified\n");
		goto out;
	}

	if ((op == OP_ADD || op == OP_APPEND) && !input_fmt) {
		printf("Input format not specified\n");
		goto out;
	}

	if (sign && !key_path) {
		printf("Key path not specified\n");
		goto out;
	}

	dirfd = open(cur_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		printf("Unable to open %s, ret: %d\n", cur_dir, dirfd);
		ret = dirfd;
		goto out;
	}

	if (op == OP_SIGN) {
		if (!list_empty(&head_in)) {
			move_path_structs(&head_out, &head_in);
		} else {
			ret = get_digest_lists(dirfd, type, &head_out);
			if (ret < 0)
				goto out;
		}

		goto out_sign;
	}

	if (op != OP_ADD || pos != -1)
		ret = process_dir(dirfd, op, type, &pos);

	if (op == OP_REMOVE)
		goto out_close;

	generator = lookup_lib(&generator_lib_head, "generator", input_fmt,
			       strlen(input_fmt));
	if (!generator) {
		printf("Unable to find generator for %s\n", input_fmt);
		goto out_close;
	}

	if (type != COMPACT_FILE)
		modifiers |= COMPACT_MOD_IMMUTABLE;

	ret = ((generator_func)generator->func)(dirfd, pos, &head_in, &head_out,
						type, modifiers, algo, ima_algo,
						tlv, alt_root);
	if (ret < 0) {
		printf("Generator %s returned %d\n", input_fmt, ret);
		goto out_free;
	}
out_sign:
	if (sign)
		ret = sign_files(dirfd, &head_out, key_path, keypass_ptr, algo);
out_free:
	free_path_structs(&head_in);
	free_path_structs(&head_out);
	free_libs(&generator_lib_head);
out_close:
	close(dirfd);
out:
	memset(keypass, 0, sizeof(keypass));
	return ret;
}
