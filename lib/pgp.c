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
 * File: pgp.c
 *      Parse PGP packets.
 */
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "pgp.h"

enum hash_algo pgp_algo_mapping[PGP_HASH__LAST] = {
	[PGP_HASH_MD5] = HASH_ALGO_MD5,
	[PGP_HASH_SHA1] = HASH_ALGO_SHA1,
	[PGP_HASH_SHA224] = HASH_ALGO_SHA224,
	[PGP_HASH_SHA256] = HASH_ALGO_SHA256,
	[PGP_HASH_SHA384] = HASH_ALGO_SHA384,
	[PGP_HASH_SHA512] = HASH_ALGO_SHA512,
};

/**
 * pgp_parse_packet_header - Parse a PGP packet header
 * @_data: Start of the PGP packet (updated to PGP packet data)
 * @_datalen: Amount of data remaining in buffer (decreased)
 * @_type: Where the packet type will be returned
 * @_headerlen: Where the header length will be returned
 *
 * Parse a set of PGP packet header [RFC 4880: 4.2].
 *
 * Returns packet data size on success; non-zero on error.  If successful,
 * *_data and *_datalen will have been updated and *_headerlen will be set to
 * hold the length of the packet header.
 */
ssize_t pgp_parse_packet_header(const u8 **_data, size_t *_datalen,
				enum pgp_packet_tag *_type,
				u8 *_headerlen)
{
	enum pgp_packet_tag type;
	const u8 *data = *_data;
	size_t size, datalen = *_datalen;

	pr_devel("-->pgp_parse_packet_header(,%zu,,)\n", datalen);

	if (datalen < 2)
		goto short_packet;

	pr_devel("pkthdr %02x, %02x\n", data[0], data[1]);

	type = *data++;
	datalen--;
	if (!(type & 0x80)) {
		pr_debug("Packet type does not have MSB set\n");
		return -EBADMSG;
	}
	type &= ~0x80;

	if (type & 0x40) {
		/* New packet length format */
		type &= ~0x40;
		pr_devel("new format: t=%u\n", type);
		switch (data[0]) {
		case 0x00 ... 0xbf:
			/* One-byte length */
			size = data[0];
			data++;
			datalen--;
			*_headerlen = 2;
			break;
		case 0xc0 ... 0xdf:
			/* Two-byte length */
			if (datalen < 2)
				goto short_packet;
			size = (data[0] - 192) * 256;
			size += data[1] + 192;
			data += 2;
			datalen -= 2;
			*_headerlen = 3;
			break;
		case 0xff:
			/* Five-byte length */
			if (datalen < 5)
				goto short_packet;
			size =  data[1] << 24;
			size |= data[2] << 16;
			size |= data[3] << 8;
			size |= data[4];
			data += 5;
			datalen -= 5;
			*_headerlen = 6;
			break;
		default:
			pr_debug("Partial body length packet not supported\n");
			return -EBADMSG;
		}
	} else {
		/* Old packet length format */
		u8 length_type = type & 0x03;
		type >>= 2;
		pr_devel("old format: t=%u lt=%u\n", type, length_type);

		switch (length_type) {
		case 0:
			/* One-byte length */
			size = data[0];
			data++;
			datalen--;
			*_headerlen = 2;
			break;
		case 1:
			/* Two-byte length */
			if (datalen < 2)
				goto short_packet;
			size  = data[0] << 8;
			size |= data[1];
			data += 2;
			datalen -= 2;
			*_headerlen = 3;
			break;
		case 2:
			/* Four-byte length */
			if (datalen < 4)
				goto short_packet;
			size  = data[0] << 24;
			size |= data[1] << 16;
			size |= data[2] << 8;
			size |= data[3];
			data += 4;
			datalen -= 4;
			*_headerlen = 5;
			break;
		default:
			pr_debug("Indefinite length packet not supported\n");
			return -EBADMSG;
		}
	}

	pr_devel("datalen=%zu size=%zu", datalen, size);
	if (datalen < size)
		goto short_packet;
	if ((int)size < 0)
		goto too_big;

	*_data = data;
	*_datalen = datalen;
	*_type = type;
	pr_devel("Found packet type=%u size=%zd\n", type, size);
	return size;

short_packet:
	pr_debug("Attempt to parse short packet\n");
	return -EBADMSG;
too_big:
	pr_debug("Signature subpacket size >2G\n");
	return -EMSGSIZE;
}

int pgp_get_signature_data(const u8 *signature, size_t signature_len,
			   u8 **data, size_t *data_len)
{
	enum pgp_packet_tag type;
	ssize_t pktlen;
	u8 headerlen;
	u8 version;

	pktlen = pgp_parse_packet_header((const u8 **)&signature,
					 &signature_len, &type, &headerlen);
	if (pktlen < 0)
		return pktlen;

	version = *signature;

	if (version == 3) {
		*data = malloc(5);
		if (*data == NULL)
			return -ENOMEM;

		memcpy(*data, signature + 2, 5);
		*data_len = 5;
	} else if (version == 4) {
		size_t hashedsz;
		u8 trailer[6];

		hashedsz = 4 + 2 + (signature[4] << 8) + signature[5];

		trailer[0] = version;
		trailer[1] = 0xffU;
		trailer[2] = hashedsz >> 24;
		trailer[3] = hashedsz >> 16;
		trailer[4] = hashedsz >> 8;
		trailer[5] = hashedsz;

		*data = malloc(hashedsz + 6);
		if (*data == NULL)
			return -ENOMEM;

		memcpy(*data, signature, hashedsz);
		memcpy(*data + hashedsz, trailer, 6);
		*data_len = hashedsz + 6;
	}

	return 0;
}

int pgp_get_digest_algo(const u8 *data, size_t datalen, u16 *algo)
{
	enum pgp_packet_tag type = PGP_PKT__HIGHEST;
	ssize_t pktlen;
	u8 headerlen;
	u8 version;

	while (datalen > 0) {
		pktlen = pgp_parse_packet_header((const u8 **)&data,
						 &datalen, &type,
						 &headerlen);
		if (pktlen < 0)
			return pktlen;

		if (type == PGP_PKT_SIGNATURE)
			break;

		datalen -= pktlen;
		data += pktlen;
	}

	if (type != PGP_PKT_SIGNATURE) {
		pr_err("Signature not found\n");
		return -EINVAL;
	}

	version = *data;

	if (version == PGP_SIG_VERSION_3) {
		const struct pgp_signature_v3_packet *v3 = (const void *)data;

		if (datalen < sizeof(*v3)) {
			pr_debug("Short V3 signature packet\n");
			return -EBADMSG;
		}

		*algo = pgp_algo_mapping[v3->hash_algo];
	} else if (version == PGP_SIG_VERSION_4) {
		const struct pgp_signature_v4_packet *v4 = (const void *)data;

		if (datalen < sizeof(*v4) + 2 + 2 + 2) {
			pr_debug("Short V4 signature packet\n");
			return -EBADMSG;
		}

		*algo = pgp_algo_mapping[v4->hash_algo];
	}

	return 0;
}

int sign_digest_list(char *path, char *key_name)
{
	char *opt = path;

	if (key_name)
		opt = "--default-key";

	if (fork() == 0) {
		return execlp("gpg", "gpg", "--yes", "--compress-algo",
			      "none", "--sign", "--detach-sign",
			      opt, key_name, path, NULL);
	}

	wait(NULL);
	return 0;
}

int dearmor_gpg(char *path)
{
	if (fork() == 0) {
		char *dest = strdup(path);

		memcpy(dest + strlen(dest) - 3, "sig", 3);
		return execlp("gpg", "gpg", "--yes", "--output", dest,
			      "--dearmor", path, NULL);
	}

	wait(NULL);
	return 0;
}

int get_default_key(char *outdir, char *key_path, char *signed_data)
{
	char output[512], keyid_value[17], *keyid_ptr, *keyid_ptr_end;
	int ret, fd[2];
	struct stat st;

	if (pipe(fd) == -1)
		return -ENOENT;

	if (fork() == 0) {
		close(STDOUT_FILENO);
		close(fd[0]);
		dup2(fd[1], STDOUT_FILENO);

		return execlp("gpg", "gpg", "--list-packets",
			      signed_data, NULL);
	}

	close(fd[1]);
	ret = read(fd[0], output, sizeof(output));
	close(fd[0]);
	wait(NULL);

	if (ret <= 0)
		return -ENOENT;

	keyid_ptr = strstr(output, "keyid");
	if (keyid_ptr) {
		keyid_ptr += strlen("keyid") + 1;
		keyid_ptr_end = strpbrk(keyid_ptr, "\n ");
		if (keyid_ptr_end) {
			*keyid_ptr_end = '\0';
			snprintf(keyid_value, sizeof(keyid_value), "%s",
				 keyid_ptr);
		}
	}

	snprintf(key_path, MAX_PATH_LENGTH, "%s/pgp-key-%s.gpg", outdir,
		 keyid_value);
	if (!stat(key_path, &st))
		return -EEXIST;

	if (fork() == 0)
		return execlp("gpg", "gpg", "--yes", "--export-options",
			      "export-minimal", "--output", key_path,
			      "--export", keyid_value, NULL);

	wait(NULL);
	return 0;
}
