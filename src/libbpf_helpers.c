// SPDX-License-Identifier: GPL-2.0
/*
 * convenience wrappers around libbpf functions
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
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

