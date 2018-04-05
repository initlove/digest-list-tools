/*
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2018 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 *   David Howells <dhowells@redhat.com>
 *   Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: pgp.h
 *      Header of pgp.c.
 */

#ifndef _PGP_H
#define _PGP_H

#include "kernel_lib.h"
#include "lib.h"

struct pgp_key_ID {
	u8 id[8];
} __attribute__((packed));

struct pgp_time {
	u8 time[4];
} __attribute__((packed));

/*
 * PGP public-key algorithm identifiers [RFC4880: 9.1]
 */
enum pgp_pubkey_algo {
	PGP_PUBKEY_RSA_ENC_OR_SIG	= 1,
	PGP_PUBKEY_RSA_ENC_ONLY		= 2,
	PGP_PUBKEY_RSA_SIG_ONLY		= 3,
	PGP_PUBKEY_ELGAMAL		= 16,
	PGP_PUBKEY_DSA			= 17,
	PGP_PUBKEY__LAST
};

/*
 * PGP symmetric-key algorithm identifiers [RFC4880: 9.2]
 */
enum pgp_symkey_algo {
	PGP_SYMKEY_PLAINTEXT		= 0,
	PGP_SYMKEY_IDEA			= 1,
	PGP_SYMKEY_3DES			= 2,
	PGP_SYMKEY_CAST5		= 3,
	PGP_SYMKEY_BLOWFISH		= 4,
	PGP_SYMKEY_AES_128KEY		= 7,
	PGP_SYMKEY_AES_192KEY		= 8,
	PGP_SYMKEY_AES_256KEY		= 9,
	PGP_SYMKEY_TWOFISH_256KEY	= 10,
};

/*
 * PGP compression algorithm identifiers [RFC4880: 9.3]
 */
enum pgp_compr_algo {
	PGP_COMPR_UNCOMPRESSED		= 0,
	PGP_COMPR_ZIP			= 1,
	PGP_COMPR_ZLIB			= 2,
	PGP_COMPR_BZIP2			= 3,
};

/*
 * PGP hash algorithm identifiers [RFC4880: 9.4]
 */
enum pgp_hash_algo {
	PGP_HASH_MD5			= 1,
	PGP_HASH_SHA1			= 2,
	PGP_HASH_RIPE_MD_160		= 3,
	PGP_HASH_SHA256			= 8,
	PGP_HASH_SHA384			= 9,
	PGP_HASH_SHA512			= 10,
	PGP_HASH_SHA224			= 11,
	PGP_HASH__LAST
};

/*
 * PGP packet type tags [RFC4880: 4.3].
 */
enum pgp_packet_tag {
	PGP_PKT_RESERVED		= 0,
	PGP_PKT_PUBKEY_ENC_SESSION_KEY	= 1,
	PGP_PKT_SIGNATURE		= 2,
	PGP_PKT_SYMKEY_ENC_SESSION_KEY	= 3,
	PGP_PKT_ONEPASS_SIGNATURE	= 4,
	PGP_PKT_SECRET_KEY		= 5,
	PGP_PKT_PUBLIC_KEY		= 6,
	PGP_PKT_SECRET_SUBKEY		= 7,
	PGP_PKT_COMPRESSED_DATA		= 8,
	PGP_PKT_SYM_ENC_DATA		= 9,
	PGP_PKT_MARKER			= 10,
	PGP_PKT_LITERAL_DATA		= 11,
	PGP_PKT_TRUST			= 12,
	PGP_PKT_USER_ID			= 13,
	PGP_PKT_PUBLIC_SUBKEY		= 14,
	PGP_PKT_USER_ATTRIBUTE		= 17,
	PGP_PKT_SYM_ENC_AND_INTEG_DATA	= 18,
	PGP_PKT_MODIFY_DETECT_CODE	= 19,
	PGP_PKT_PRIVATE_0		= 60,
	PGP_PKT_PRIVATE_3		= 63,
	PGP_PKT__HIGHEST		= 63
};

/*
 * Signature (tag 2) packet [RFC4880: 5.2].
 */
enum pgp_signature_version {
	PGP_SIG_VERSION_3			= 3,
	PGP_SIG_VERSION_4			= 4,
};

enum pgp_signature_type {
	PGP_SIG_BINARY_DOCUMENT_SIG		= 0x00,
	PGP_SIG_CANONICAL_TEXT_DOCUMENT_SIG	= 0x01,
	PGP_SIG_STANDALONE_SIG			= 0x02,
	PGP_SIG_GENERAL_CERT_OF_UID_PUBKEY	= 0x10,
	PGP_SIG_PERSONAL_CERT_OF_UID_PUBKEY	= 0x11,
	PGP_SIG_CASUAL_CERT_OF_UID_PUBKEY	= 0x12,
	PGP_SIG_POSTITIVE_CERT_OF_UID_PUBKEY	= 0x13,
	PGP_SIG_SUBKEY_BINDING_SIG		= 0x18,
	PGP_SIG_PRIMARY_KEY_BINDING_SIG		= 0x19,
	PGP_SIG_DIRECTLY_ON_KEY			= 0x1F,
	PGP_SIG_KEY_REVOCATION_SIG		= 0x20,
	PGP_SIG_SUBKEY_REVOCATION_SIG		= 0x28,
	PGP_SIG_CERT_REVOCATION_SIG		= 0x30,
	PGP_SIG_TIMESTAMP_SIG			= 0x40,
	PGP_SIG_THIRD_PARTY_CONFIRM_SIG		= 0x50,
};

struct pgp_signature_v3_packet {
	enum pgp_signature_version version : 8; /* == PGP_SIG_VERSION_3 */
	u8	length_of_hashed;	/* == 5 */
	struct {
		enum pgp_signature_type signature_type : 8;
		struct pgp_time	creation_time;
	} __attribute__((packed)) hashed;
	struct pgp_key_ID issuer;
	enum pgp_pubkey_algo pubkey_algo : 8;
	enum pgp_hash_algo hash_algo : 8;
} __attribute__((packed));

struct pgp_signature_v4_packet {
	enum pgp_signature_version version : 8;	/* == PGP_SIG_VERSION_4 */
	enum pgp_signature_type signature_type : 8;
	enum pgp_pubkey_algo pubkey_algo : 8;
	enum pgp_hash_algo hash_algo : 8;
} __attribute__((packed));

extern enum hash_algo pgp_algo_mapping[PGP_HASH__LAST];

int pgp_get_signature_data(const u8 *signature, size_t signature_len,
			   u8 **data, size_t *data_len);
int pgp_get_digest_algo(const u8 *data, size_t datalen, u16 *algo);
int sign_digest_list(char *path, char *key_name);
int dearmor_gpg(char *path);
int get_default_key(char *outdir, char *key_path, char *signed_data);
#endif /* _PGP_H */
