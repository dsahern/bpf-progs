// SPDX-License-Identifier: GPL-2.0
/*
 * convenience wrappers around libbpf functions
 *
 * Copyright (c) 2019-2021 David Ahern <dsahern@gmail.com>
 */

#include <linux/if_link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

#include "libbpf_helpers.h"

enum bpf_obj_type {
	BPF_OBJ_UNKNOWN,
	BPF_OBJ_PROG,
	BPF_OBJ_MAP,
	BPF_OBJ_LINK,
	BPF_OBJ_BTF,
};

int load_obj_file(struct bpf_prog_load_attr *attr,
		  struct bpf_object **obj,
		  const char *objfile, bool user_set)
{
	static char *expected_paths[] = {
		"bin",
		"ksrc/obj",	/* path in git tree */
		"bpf-obj",
		".",		/* cwd */
		NULL,
	};
	char path[PATH_MAX];
	int prog_fd, i = 0;

	if (user_set) {
		attr->file = objfile;
		return bpf_prog_load_xattr(attr, obj, &prog_fd);
	}

	attr->file = path;
	while (expected_paths[i]) {
		struct stat sbuf;

		snprintf(path, sizeof(path), "%s/%s",
			 expected_paths[i], objfile);

		if (stat(path, &sbuf) == 0) {
			if (!bpf_prog_load_xattr(attr, obj, &prog_fd))
				return 0;

			if (errno != ENOENT)
				break;
		}
		++i;
	}

	fprintf(stderr, "Failed to find object file; nothing to load\n");
	return 1;
}

int bpf_map_get_fd_by_name(const char *name)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	__u32 id = 0;
	int err, fd;

	while (1) {
		err = bpf_map_get_next_id(id, &id);
		if (err)
			break;

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0)
			continue;

		err = bpf_obj_get_info_by_fd(fd, &info, &len);
		if (!err && strcmp(info.name, name) == 0)
			return fd;

		close(fd);
	}

	return -1;
}

/* from bpftool */
static int get_fd_type(int fd)
{
	char path[PATH_MAX];
	char buf[512];
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

	n = readlink(path, buf, sizeof(buf));
	if (n < 0) {
		fprintf(stderr, "can't read link type: %s\n", strerror(errno));
		return -1;
	}
	if (n == sizeof(path)) {
		fprintf(stderr, "can't read link type: path too long!\n");
		return -1;
	}

	if (strstr(buf, "bpf-map"))
		return BPF_OBJ_MAP;

	if (strstr(buf, "bpf-prog"))
		return BPF_OBJ_PROG;

	if (strstr(buf, "bpf-link"))
		return BPF_OBJ_LINK;

	return BPF_OBJ_UNKNOWN;
}

int bpf_map_get_fd_by_path(const char *path)
{
	enum bpf_obj_type objtype;
	int fd;

	fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr, "Failed to get bpf object (%s): %s\n",
			path, strerror(errno));
		return -1;
	}

	objtype = get_fd_type(fd);
	if (objtype != BPF_OBJ_MAP) {
		fprintf(stderr, "Path is not to a BPF map\n");
		close(fd);
		return -1;
	}

	return fd;
}

int bpf_map_get_fd(__u32 id, const char *path, const char *name,
		   const char *desc)
{
	int fd = -1;

	if (id) {
		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0 && errno != ENOENT) {
			fprintf(stderr,
				"Failed to get fd for %s by id: %s: %d\n",
				desc, strerror(errno), errno);
			return -1;
		}
	} else if (path) {
		fd = bpf_map_get_fd_by_path(path);
		if (fd < 0) {
			fprintf(stderr,
				"Failed to get fd for %s by path: %s: %d\n",
				desc, strerror(errno), errno);
			return -1;
		}
	} else if (name) {
		fd = bpf_map_get_fd_by_name(name);
		if (fd < 0 && errno != ENOENT) {
			fprintf(stderr,
				"Failed to get fd for %s by expected name: %s: %d\n",
				desc, strerror(errno), errno);
			return -1;
		}
	}

	return fd;
}

int bpf_prog_get_fd_by_path(const char *path)
{
	enum bpf_obj_type objtype;
	int fd;

	fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr, "Failed to get bpf object (%s): %s\n",
			path, strerror(errno));
		return -1;
	}

	objtype = get_fd_type(fd);
	if (objtype != BPF_OBJ_PROG) {
		fprintf(stderr, "Path is not to a BPF program\n");
		close(fd);
		return -1;
	}

	return fd;
}

int bpf_prog_get_fd_by_name(const char *name)
{
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);
	__u32 id = 0;
	int err, fd;

	while (1) {
		err = bpf_prog_get_next_id(id, &id);
		if (err)
			break;

		fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0)
			continue;

		err = bpf_obj_get_info_by_fd(fd, &info, &len);
		if (!err && strcmp(info.name, name) == 0)
			return fd;

		close(fd);
	}

	return -1;
}

int bpf_prog_get_fd(__u32 id, const char *path, const char *name,
		    const char *desc)
{
	int fd = -1;

	if (id) {
		fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0 && errno != ENOENT) {
			fprintf(stderr,
				"Failed to get fd for %s by id: %s: %d\n",
				desc, strerror(errno), errno);
			return -1;
		}
	} else if (path) {
		fd = bpf_prog_get_fd_by_path(path);
		if (fd < 0) {
			fprintf(stderr,
				"Failed to get fd for %s by path: %s: %d\n",
				desc, strerror(errno), errno);
			return -1;
		}
	} else if (name) {
		fd = bpf_prog_get_fd_by_name(name);
		if (fd < 0 && errno != ENOENT) {
			fprintf(stderr,
				"Failed to get fd for %s by expected name: %s: %d\n",
				desc, strerror(errno), errno);
			return -1;
		}
	}

	return fd;
}

int attach_to_dev_generic(int idx, int prog_fd, const char *dev)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, prog_fd, XDP_FLAGS_SKB_MODE);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", dev);
		return err;
	}

	return 0;
}

int detach_from_dev_generic(int idx, const char *dev)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, -1, XDP_FLAGS_SKB_MODE);
	if (err < 0)
		printf("ERROR: failed to detach program from %s\n", dev);

	return 0;
}


int attach_to_dev(int idx, int prog_fd, const char *dev)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, prog_fd, XDP_FLAGS_DRV_MODE);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", dev);
		return err;
	}

	return 0;
}

int detach_from_dev(int idx, const char *dev)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, -1, 0);
	if (err < 0)
		printf("ERROR: failed to detach program from %s\n", dev);

	return 0;
}
