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
 * File: compact_list.h
 *      Header of compact_list.c.
 */

#ifndef _COMPACT_LIST_H
#define _COMPACT_LIST_H

#include "lib.h"

#define COMPACT_LIST_SIZE_MAX 64 * 1024 * 1024 - 1
#define IMA_KEY_PATH "/etc/keys/x509_ima.der"

enum parser_ops { PARSER_OP_ADD_DIGEST, PARSER_OP_ADD_DIGEST_TO_HTABLE,
		  PARSER_OP_UPDATE_DIGEST, PARSER_OP_RESTORE_FILES,
		  PARSER_OP_ADD_META_DIGEST,
		  PARSER_OP_ADD_META_DIGEST_TO_HTABLE,
		  PARSER_OP_ADD_IMA_XATTR, PARSER_OP_REMOVE_IMA_XATTR,
		  PARSER_OP_ADD_EVM_XATTR,  PARSER_OP_REMOVE_EVM_XATTR,
		  PARSER_OP_REMOVE_INFOFLOW_XATTR, PARSER_OP_VERIFY,
		  PARSER_OP_DUMP, PARSER_OP_GEN_IMA_LIST, PARSER_OP_CHECK_META,
		  PARSER_OP_REPAIR_META, PARSER_OP_REPAIR_META_DIGEST_LISTS,
		  PARSER_OP__LAST };

enum tlv_ids { ID_DIGEST, ID_EVM_DIGEST, ID_PATH, ID_INODE_UID, ID_INODE_GID,
	       ID_INODE_MODE, ID_INODE_SIZE, ID_FSMAGIC, ID_OBJ_LABEL, ID_CAPS,
	       ID__LAST };

struct _tlv_item {
	u8 id;
	u32 len;
	u8 data[];
} __attribute__((packed));

struct tlv_item {
	struct list_head list;
	struct _tlv_item *item;
};

extern char *compact_types_str[COMPACT__LAST];
extern char *compact_modifiers_str[COMPACT_MOD__LAST];

struct list_struct {
	struct list_head list;
	struct compact_list_hdr *hdr;
};

struct list_struct *compact_list_init(struct list_head *head,
				      enum compact_types type, u16 modifiers,
				      enum hash_algo algo, bool tlv);
int compact_list_add_digest(int fd, struct list_struct *list, u8 *digest);

int compact_list_tlv_add_digest(int fd, struct list_struct *list,
				struct list_head *head, u8 *digest,
				enum tlv_ids id);
int compact_list_tlv_add_metadata(int fd, struct list_struct *list,
				  struct list_head *head, char *path,
				  char *alt_root, struct stat *stat,
				  char *obj_label, int obj_label_len,
				  u8 *caps_bin, int caps_bin_len);
int compact_list_tlv_add_item(int fd, struct list_struct *list,
			      struct list_head *head, enum tlv_ids id,
			      size_t len, u8 *data);
int compact_list_tlv_add_items(int fd, struct list_struct *list,
			       struct list_head *head);
void compact_list_tlv_dump_items(struct _tlv_item **items);
void compact_list_tlv_free_items(struct list_head *head);

int compact_list_upload(int fd, struct list_struct *list);
int compact_list_flush_all(int fd, struct list_head *list_head);

typedef int (*generator_func)(int dirfd, int pos, struct list_head *head_in,
			      struct list_head *head_out,
			      enum compact_types type, u16 modifiers,
			      enum hash_algo algo, enum hash_algo ima_algo,
			      bool tlv, char *alt_root);
typedef int (*parser_func)(int imafd, struct list_head *head,
			   loff_t size, void *buf, enum parser_ops op,
			   char *backup_dir);

int gen_filename_prefix(char *filename, int filename_len, int pos,
			const char *format, enum compact_types type);

typedef int (*filter_lists)(const struct dirent *file);

int filter_parser_list_symlink(const struct dirent *file);
extern filter_lists filter[COMPACT__LAST];
int get_digest_lists(int dirfd, enum compact_types type,
		     struct list_head *head);
int compare_lists(const struct dirent **e1, const struct dirent **e2);

int digest_list_add_metadata(int dirfd, int fd, char *digest_list_filename,
			     char *digest_list_dir, struct list_head *head,
			     u8 *digest_list_buf, size_t digest_list_buf_len);
int digest_list_upload(int dirfd, int fd, struct list_head *head,
		       struct list_head *parser_lib_head,
		       char *digest_list_filename, enum parser_ops op,
		       char *backup_dir, char *digest_lists_dir);
int process_lists(int dirfd, int fd, int save, int verbose,
		  struct list_head *head, enum compact_types type,
		  enum parser_ops op, char *backup_dir, char *digest_lists_dir,
		  char *filename);

#endif /*_COMPACT_LIST_H*/
