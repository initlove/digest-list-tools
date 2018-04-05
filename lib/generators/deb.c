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
 * File: deb.c
 *      Writes DEB digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <curl/curl.h>

#include "kernel_lib.h"
#include "deb.h"
#include "pgp.h"

static int download_file(char *url, char *path)
{
	FILE *f;
	int ret = -EINVAL;

	CURL *curl;
	CURLcode res;

	f = fopen(path, "wb");
	if (!f) {
		pr_err("Failed to create %s\n", path);
		return ret;
	}

	pr_info("Downloading %s\n", url);

	curl = curl_easy_init();
	if (!curl)
		goto out;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)f);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

	res = curl_easy_perform(curl);
	if(res != CURLE_OK) {
		pr_err("curl_easy_perform() failed: %s\n",
		       curl_easy_strerror(res));
		goto out;
	}

	ret = 0;
out:
	curl_easy_cleanup(curl);
	fclose(f);
	return ret;
}

static void replace_slash(char *path)
{
	char *path_ptr = path;

	while ((path_ptr = strchr(path_ptr, '/')))
		*path_ptr++ = '-';
}

static int download_deb_package(char *distro, char *repo_url, char *outdir,
				char *package_path, char *digest_list_path,
				u8 *digest)
{
	char url[MAX_PATH_LENGTH + 1];
	char *file_ptr = strrchr(package_path, '/');
	int ret;

	snprintf(url, sizeof(url), "%s/%s", repo_url, package_path);
	snprintf(digest_list_path, MAX_PATH_LENGTH, "%s/%s",
		 outdir, file_ptr);

	ret = check_digest(NULL, 0, digest_list_path, ima_hash_algo, digest);
	if (!ret)
		return ret;

	return download_file(url, digest_list_path);
}

static int download_deb_packages_gz(char *distro, char *repo_url, char *outdir,
				    char *packages_gz_path,
				    char *digest_list_path)
{
	char url[MAX_PATH_LENGTH];

	snprintf(url, sizeof(url), "%s/dists/%s/%s", repo_url, distro,
		 packages_gz_path);

	replace_slash(packages_gz_path);

	snprintf(digest_list_path, MAX_PATH_LENGTH, "%s/%s-%s",
		 outdir, distro, packages_gz_path);

	return download_file(url, digest_list_path);
}

static int download_deb_release(char *distro, char *repo_url, char *outdir,
				char *digest_list_path)
{
	char url[MAX_PATH_LENGTH];
	char path[MAX_PATH_LENGTH];
	int ret;

	snprintf(url, sizeof(url), "%s/dists/%s/Release", repo_url, distro);
	snprintf(digest_list_path, MAX_PATH_LENGTH, "%s/%s-Release",
		 outdir, distro);

	ret = download_file(url, digest_list_path);
	if (ret < 0)
		return ret;

	snprintf(url, sizeof(url), "%s/dists/%s/Release.gpg", repo_url, distro);
	snprintf(path, sizeof(path), "%s/%s-Release.asc", outdir, distro);

	ret = download_file(url, path);
	if (!ret)
		ret = dearmor_gpg(path);

	return ret;
}

struct pkg_entry {
	char *pkg;
	int digests_added;
	struct pkg_entry *next;
};

struct deb_ctx {
	char *distro;
	char *repo_url;
	char *outdir;
	char *metadata_path;
	char *arch;
	char path[MAX_PATH_LENGTH];
	int check_packages;
	int packages_found;
	struct pkg_entry *packages;
};

static int deb_packages_gz_callback(void *ctx, char *line)
{
	char digest_list_path[MAX_PATH_LENGTH], *file_ptr, *digest_ptr;
	const char *filename_str = "Filename: ";
	int ret = 0, filename_str_len = strlen(filename_str);
	struct deb_ctx *c = (struct deb_ctx *)ctx;
	struct pkg_entry *entry = c->packages;
	const char *algo_name = hash_algo_name[ima_hash_algo];
	u8 digest[IMA_MAX_DIGEST_SIZE];

	if (!strncmp(line, filename_str, filename_str_len)) {
		snprintf(c->path, sizeof(c->path), "%s",
			 line + filename_str_len);
		return 0;
	}

	if (strncasecmp(line, algo_name, strlen(algo_name)))
		return 0;

	file_ptr = strrchr(c->path, '/') + 1;
	digest_ptr = strchr(line, ':') + 2;

	hex2bin(digest, digest_ptr, hash_digest_size[ima_hash_algo]);

	while (entry) {
		if (strcmp(file_ptr, entry->pkg)) {
			entry = entry->next;
			continue;
		}

		if (entry->digests_added) {
			entry = entry->next;
			continue;
		}

		if (c->check_packages) {
			c->packages_found = 1;
			return 0;
		}

		ret = download_deb_package(c->distro, c->repo_url, c->outdir,
					   c->path, digest_list_path, digest);
		if (ret < 0)
			return ret;

		ret = write_digests_and_metadata(c->outdir, c->metadata_path,
						 digest_list_path,
						 DATA_SUB_TYPE_DEB_PACKAGE, 0);
		if (!ret)
			entry->digests_added = 1;

		break;
	}

	return ret;
}

static int deb_release_callback(void *ctx, char *line)
{
	struct deb_ctx *c = (struct deb_ctx *)ctx;
	char digest_list_path[MAX_PATH_LENGTH];
	const char *packages_gz_str = "Packages.gz";
	int l_gz = strlen(packages_gz_str);
	char *size_ptr, *file_ptr;
	loff_t len;
	void *buf;
	int ret, fd;

	size_ptr = line + 1 + hash_digest_size[ima_hash_algo] * 2;
	file_ptr = size_ptr + 18;

	if (!strstr(file_ptr, c->arch))
		return 0;

	if (strncmp(file_ptr + strlen(file_ptr) - l_gz, packages_gz_str, l_gz))
		return 0;

	ret = download_deb_packages_gz(c->distro, c->repo_url, c->outdir,
				       file_ptr, digest_list_path);
	if (ret < 0)
		return ret;

	fd = read_file_from_path(digest_list_path, &buf, &len);
	if (fd < 0)
		return fd;

	c->check_packages = 1;
	c->packages_found = 0;

	ret = ima_parse_deb_packages_gz(len, buf, ima_hash_algo, ctx,
					deb_packages_gz_callback);
	if (ret < 0)
		goto out;

	if (!c->packages_found) {
		unlink(digest_list_path);
		goto out;
	}

	ret = write_digests_and_metadata(c->outdir, c->metadata_path,
					 digest_list_path,
					 DATA_SUB_TYPE_DEB_PACKAGES_GZ, 0);
	if (ret < 0)
		goto out;

	c->check_packages = 0;

	ret = ima_parse_deb_packages_gz(len, buf, ima_hash_algo, ctx,
					deb_packages_gz_callback);
out:
	munmap(buf, len);
	close(fd);
	return ret;
}

int digest_list_from_deb_mirror(char *outdir, char *metadata_path,
				enum digest_data_sub_types output_fmt,
				char *distro, char *repo_url)
{
	char digest_list_path[MAX_PATH_LENGTH];
	char *distro_suffix[] = {"", "-updates", "-security"};
	char repo[MAX_PATH_LENGTH], pkg_filename[MAX_PATH_LENGTH];
	struct deb_ctx ctx = {repo, repo_url, outdir,
			      metadata_path, "amd64", {0}, 0, 0};
	struct pkg_entry *entry, *next_entry;
	loff_t len;
	void *buf;
	char *line = NULL;
	char *pkg_name_ptr, *pkg_ver_ptr, *pkg_arch_ptr, *pkg_epoch_end;
	size_t line_len, cur_len;
	int i, fd, ret = 0;

	FILE *f = popen(DPKG_QUERY_CMD, "r");
	if (f == NULL) {
		pr_err("Unable to execute dpkg-query\n");
		return -EPERM;
	}

	curl_global_init(CURL_GLOBAL_DEFAULT);

	while ((cur_len = getline(&line, &line_len, f)) != -1) {
		entry = malloc(sizeof(*entry));
		if (!entry) {
			ret = -ENOMEM;
			goto out;
		}

		line[cur_len - 1] = '\0';
		pkg_name_ptr = line;
		pkg_ver_ptr = strchr(pkg_name_ptr, ' ');
		*pkg_ver_ptr++ = '\0';
		pkg_epoch_end = strchr(pkg_ver_ptr, ':');
		if (pkg_epoch_end)
			pkg_ver_ptr = pkg_epoch_end + 1;

		pkg_arch_ptr = strchr(pkg_ver_ptr, ' ');
		*pkg_arch_ptr++ = '\0';

		snprintf(pkg_filename, sizeof(pkg_filename), "%s_%s_%s.deb",
			 pkg_name_ptr, pkg_ver_ptr, pkg_arch_ptr);
		entry->pkg = strdup(pkg_filename);
		if (!entry->pkg) {
			free(entry);
			goto out;
		}

		entry->digests_added = 0;
		entry->next = ctx.packages;
		ctx.packages = entry;
	}

	for (i = 0; i < ARRAY_SIZE(distro_suffix); i++) {
		snprintf(repo, sizeof(repo), "%s%s", distro, distro_suffix[i]);

		ret = download_deb_release(repo, repo_url, outdir,
					   digest_list_path);
		if (ret < 0)
			goto out;

		ret = write_digests_and_metadata(outdir, metadata_path,
						 digest_list_path,
						 DATA_SUB_TYPE_DEB_RELEASE, 0);
		if (ret < 0)
			goto out;

		fd = read_file_from_path(digest_list_path, &buf, &len);
		if (fd < 0)
			goto out;

		ret = ima_parse_deb_release(len, buf, ima_hash_algo,
					    &ctx, deb_release_callback);

		munmap(buf, len);
		close(fd);

		if (ret < 0)
			goto out;
	}
out:
	pclose(f);
	entry = ctx.packages;

	while(entry) {
		if (!entry->digests_added)
			pr_err("Warning: digests not added for package %s\n",
			       entry->pkg);
		next_entry = entry->next;
		free(entry->pkg);
		free(entry);
		entry = next_entry;
	}

	curl_global_cleanup();

	return 0;
}
