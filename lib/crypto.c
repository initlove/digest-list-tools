/*
 * Copyright (C) 2011 Nokia Corporation
 * Copyright (C) 2011,2012,2013 Intel Corporation
 * Copyright (C) 2013,2014 Samsung Electronics
 * Copyright (C) 2017-2020 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 * Dmitry Kasatkin <dmitry.kasatkin@nokia.com>
 *                 <dmitry.kasatkin@intel.com>
 *                 <d.kasatkin@samsung.com>
 * Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: crypto.c
 *      Calculate file digest.
 */

#include "crypto.h"
#include "xattr.h"


int calc_digest(u8 *digest, void *data, u64 len, enum hash_algo algo)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	int ret = -EINVAL;

	OpenSSL_add_all_algorithms();

	md = EVP_get_digestbyname(hash_algo_name[algo]);
	if (!md)
		goto out;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
		goto out;

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
		goto out_mdctx;

	if (EVP_DigestUpdate(mdctx, data, len) != 1)
		goto out_mdctx;

	if (EVP_DigestFinal_ex(mdctx, digest, NULL) != 1)
		goto out_mdctx;

	ret = 0;
out_mdctx:
	EVP_MD_CTX_destroy(mdctx);
out:
	EVP_cleanup();
	return ret;
}

int calc_file_digest(u8 *digest, int dirfd, char *path, enum hash_algo algo)
{
	void *data = MAP_FAILED;
	struct stat st;
	int fd, ret = 0;

	if (dirfd >= 0) {
		if (fstatat(dirfd, path, &st, 0) == -1)
			return -EACCES;

		fd = openat(dirfd, path, O_RDONLY);
	} else {
		if (stat(path, &st) == -1)
			return -EACCES;

		fd = open(path, O_RDONLY);
	}

	if (fd < 0)
		return -EACCES;

	if (st.st_size) {
		data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (data == MAP_FAILED) {
			ret = -ENOMEM;
			goto out;
		}
	}

	ret = calc_digest(digest, data, st.st_size, algo);
out:
	if (data != MAP_FAILED)
		munmap(data, st.st_size);

	close(fd);
	return ret;
}

struct RSA_ASN1_template {
	const uint8_t *data;
	size_t size;
};

/*
 * Hash algorithm OIDs plus ASN.1 DER wrappings [RFC4880 sec 5.2.2].
 */
static const uint8_t RSA_digest_info_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x0E, 0x03, 0x02, 0x1A,
	0x05, 0x00, 0x04, 0x14
};

static const uint8_t RSA_digest_info_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x20
};

static const uint8_t RSA_digest_info_SHA512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
	0x05, 0x00, 0x04, 0x40
};

const struct RSA_ASN1_template RSA_ASN1_templates[HASH_ALGO__LAST] = {
#define _(X) { RSA_digest_info_##X, sizeof(RSA_digest_info_##X) }
	[HASH_ALGO_SHA1]	= _(SHA1),
	[HASH_ALGO_SHA256]	= _(SHA256),
	[HASH_ALGO_SHA512]	= _(SHA512),
#undef _
};

static void free_key(struct key_struct *k)
{
	RSA_free(k->key);
	free(k);
}

void free_keys(struct list_head *head)
{
	struct key_struct *cur, *tmp;

	list_for_each_entry_safe(cur, tmp, head, list) {
		list_del(&cur->list);
		free_key(cur);
	}
}

struct key_struct *new_key(struct list_head *head, int dirfd, char *key_path,
			   char *keypass, bool private)
{
	u8 digest[SHA512_DIGEST_SIZE], *pkey = NULL;
	struct key_struct *new = NULL;
	EVP_PKEY *public_key = NULL;
	X509 *crt = NULL;
	FILE *fp;
	int ret = -EINVAL, fd, pkey_len;

	OpenSSL_add_all_algorithms();

	if (dirfd != -1)
		fd = openat(dirfd, key_path, O_RDONLY);
	else
		fd = open(key_path, O_RDONLY);

	if (fd < 0)
		goto out;

	fp = fdopen(fd, "r");
	if (!fp) {
		ret = -EACCES;
		close(fd);
		goto out;
	}

	new = calloc(1, sizeof(*new));
	if (!new) {
		ret = -ENOMEM;
		goto out_fp;
	}

	if (private)
		new->key = PEM_read_RSAPrivateKey(fp, NULL, NULL,
						  (void *)keypass);
	else {
		crt = d2i_X509_fp(fp, NULL);
		if (!crt) {
			printf("d2i_X509_fp() failed\n");
			goto out_fp;
		}
		public_key = X509_extract_key(crt);
		if (!public_key) {
			printf("X509_extract_key() failed\n");
			goto out_fp;
		}
		new->key = EVP_PKEY_get1_RSA(public_key);
	}

	if (!new->key) {
		ret = -ENOENT;
		goto out_key;
	}

	pkey_len = i2d_RSAPublicKey(new->key, &pkey);
	if (pkey_len < 0) {
		printf("Cannot extract public key\n");
		goto out_key;
	}

	ret = calc_digest(digest, pkey, pkey_len, HASH_ALGO_SHA1);

	memcpy(new->keyid, digest + 16, 4);
	list_add_tail(&new->list, head);
	free(pkey);
out_key:
	if (ret < 0) {
		free_key(new);
		new = NULL;
	}
out_fp:
	if (public_key)
		EVP_PKEY_free(public_key);
	if (crt)
		X509_free(crt);
	fclose(fp);
out:
	EVP_cleanup();
	return new;
}

struct key_struct *lookup_key(struct list_head *head, int dirfd, char *key_path,
			      u8 *keyid)
{
	struct key_struct *cur = NULL;

	list_for_each_entry(cur, head, list)
		if (!memcmp(cur->keyid, keyid, sizeof(cur->keyid)))
			return cur;

	if (key_path)
		return cur;

	return new_key(head, dirfd, key_path, NULL, false);
}

static int sign_file(int dirfd, char *filename, char *key_path, char *keypass,
		     enum hash_algo algo)
{
	u8 digest[SHA512_DIGEST_SIZE], sig[MAX_SIGNATURE_SIZE];
	const struct RSA_ASN1_template *asn1;
	struct key_struct *k;
	LIST_HEAD(key_head);
	u8 *buf;
	int ret = 0, digest_len, sig_len;

	k = new_key(&key_head, -1, key_path, keypass, true);
	if (!k)
		return -ENOENT;

	ret = calc_file_digest(digest, dirfd, filename, algo);
	if (ret < 0)
		goto out_key;

	digest_len = hash_digest_size[algo];

	asn1 = &RSA_ASN1_templates[algo];
	if (!asn1) {
		printf("Algorithm %s not supported\n", hash_algo_name[algo]);
		goto out_key;
	}

	buf = malloc(digest_len + asn1->size);
	if (!buf) {
		ret = -ENOMEM;
		goto out_key;
	}

	memcpy(buf, asn1->data, asn1->size);
	memcpy(buf + asn1->size, digest, digest_len);

	sig_len = RSA_private_encrypt(digest_len + asn1->size, buf, sig, k->key,
				      RSA_PKCS1_PADDING);
	if (sig_len < 0) {
		printf("RSA_private_encrypt() failed: %d\n", sig_len);
		goto out_buf;
	}

	ret = write_ima_xattr(dirfd, filename, k->keyid, sizeof(k->keyid),
			      sig, sig_len, algo);
out_buf:
	free(buf);
out_key:
	free_keys(&key_head);
	return ret;
}

int sign_files(int dirfd, struct list_head *head, char *key_path,
	       char *keypass, enum hash_algo algo)
{
	struct path_struct *cur;
	int ret = 0;

	list_for_each_entry(cur, head, list) {
		ret = sign_file(dirfd, cur->path, key_path, keypass, algo);
		if (ret < 0) {
			printf("Cannot sign %s\n", cur->path);
			return ret;
		}
	}

	return ret;
}

static int verify_common(struct list_head *head, int dirfd, char *filename,
			 u8 *sig_in, int sig_in_len, u8 *digest_in,
			 enum hash_algo algo_in)
{
	u8 *buf = NULL, *keyid, *sig;
	u8 digest[SHA512_DIGEST_SIZE], out[MAX_SIGNATURE_SIZE];
	enum hash_algo algo;
	struct key_struct *k;
	const struct RSA_ASN1_template *asn1;
	size_t buf_len, keyid_len, sig_len, len;
	int ret;

	if (filename) {
		ret = read_ima_xattr(dirfd, filename, &buf, &buf_len, &keyid,
				     &keyid_len, &sig, &sig_len, &algo);
		if (ret < 0) {
			printf("Cannot read security.ima xattr: %d\n", ret);
			return ret;
		}

		ret = calc_file_digest(digest, dirfd, filename, algo);
		if (ret < 0)
			goto out;
	} else {
		ret = parse_ima_xattr(sig_in, sig_in_len, &keyid, &keyid_len,
				      &sig, &sig_len, &algo);
		if (ret) {
			printf("Cannot parse security.ima xattr: %d\n", ret);
			return ret;
		}

		if (algo != algo_in) {
			printf("Hash algorithm mismatch\n");
			return -EINVAL;
		}

		memcpy(digest, digest_in, hash_digest_size[algo]);
	}

	k = lookup_key(head, dirfd, NULL, keyid);
	if (!k) {
		printf("No key found for id %d\n", be32_to_cpu(keyid));
		ret = -ENOENT;
		goto out;
	}

	ret = RSA_public_decrypt(sig_len, sig, out, k->key, RSA_PKCS1_PADDING);
	if (ret < 0) {
		printf("RSA_public_decrypt() failed: %d\n", ret);
		goto out;
	}

	len = ret;

	asn1 = &RSA_ASN1_templates[algo];

	if (len < asn1->size || memcmp(out, asn1->data, asn1->size)) {
		printf("Verification failed: %d (asn1 mismatch)\n", ret);
		goto out;
	}

	len -= asn1->size;

	if (memcmp(out + asn1->size, digest, hash_digest_size[algo])) {
		printf("Verification failed (digest mismatch)\n");
		ret = -EINVAL;
		goto out;
	}

	ret = 0;
out:
	free(buf);
	return ret;
}

int verify_file(struct list_head *head, int dirfd, char *filename)
{
	return verify_common(head, dirfd, filename, NULL, 0, NULL,
			     HASH_ALGO__LAST);
}

int verify_sig(struct list_head *head, int dirfd, u8 *sig, int sig_len,
	       u8 *digest, enum hash_algo algo)
{
	return verify_common(head, dirfd, NULL, sig, sig_len, digest, algo);
}
