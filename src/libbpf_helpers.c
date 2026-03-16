// SPDX-License-Identifier: GPL-2.0
/*
 * convenience wrappers around libbpf functions
 *
 * Copyright (c) 2019-2021 David Ahern <dsahern@gmail.com>
 */

#include <linux/if_link.h>
#include <linux/kernel.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

#include "linux_utils.h"
#include "libbpf_helpers.h"

enum bpf_obj_type {
	BPF_OBJ_UNKNOWN,
	BPF_OBJ_PROG,
	BPF_OBJ_MAP,
	BPF_OBJ_LINK,
	BPF_OBJ_BTF,
};

int load_obj_file(const char *objfile, bool user_set,
		  struct bpf_object **pobj)
{
	static char *expected_paths[] = {
		"bin",
		"ksrc/obj",	/* path in git tree */
		"bpf-obj",
		".",		/* cwd */
	};
	//char log_buf[128];
	struct bpf_object_open_opts opts = {
		.sz = sizeof(opts),
		//.kernel_log_buf = log_buf,
		//.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 4,
	};
	struct bpf_object *obj;
	int i;

	if (user_set) {
		obj = bpf_object__open_file(objfile, &opts);
		if (!obj)
			return -1;
	} else {
		char path[PATH_MAX];

		obj = NULL;
		for (i = 0; i < ARRAY_SIZE(expected_paths); ++i) {
			struct stat sbuf;

			snprintf(path, sizeof(path), "%s/%s",
				 expected_paths[i], objfile);

			if (stat(path, &sbuf))
				continue;

			obj = bpf_object__open_file(objfile, &opts);
			if (obj)
				break;
		}
	}

	if (!obj) {
		fprintf(stderr, "Failed to find object file\n");
		return -1;
	}

	//if (bpf_object__prepare(obj)) {
	//	fprintf(stderr, "Failed to prepare object for loading\n");
	//	goto err_out;
	//}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "Failed to load object\n");
		goto err_out;
	}

	*pobj = obj;
	return 0;

err_out:
	bpf_object__close(obj);
	return -1;
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

	err = bpf_xdp_attach(idx, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", dev);
		return err;
	}

	return 0;
}

int detach_from_dev_generic(int idx, const char *dev)
{
	int err;

	err = bpf_xdp_detach(idx, XDP_FLAGS_SKB_MODE, NULL);
	if (err < 0)
		printf("ERROR: failed to detach program from %s\n", dev);

	return 0;
}


int attach_to_dev(int idx, int prog_fd, const char *dev)
{
	int err;

	err = bpf_xdp_attach(idx, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", dev);
		return err;
	}

	return 0;
}

int detach_from_dev(int idx, const char *dev)
{
	int err;

	err = bpf_xdp_detach(idx, XDP_FLAGS_DRV_MODE, NULL);
	if (err < 0)
		printf("ERROR: failed to detach program from %s\n", dev);

	return 0;
}
