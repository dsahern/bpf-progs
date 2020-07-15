/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LIBBPF_HELPERS_H
#define __LIBBPF_HELPERS_H

#include <bpf/libbpf.h>

enum bpf_obj_type {
	BPF_OBJ_UNKNOWN,
	BPF_OBJ_PROG,
	BPF_OBJ_MAP,
	BPF_OBJ_LINK,
	BPF_OBJ_BTF,
};

int load_obj_file(struct bpf_prog_load_attr *attr,
                  struct bpf_object **obj,
                  const char *objfile, bool user_set);

int bpf_map_get_fd_by_name(const char *name);
int bpf_map_get_fd_by_path(const char *path);

int bpf_prog_get_fd_by_path(const char *path);

int attach_to_dev_generic(int idx, int prog_fd, const char *dev);
int detach_from_dev_generic(int idx, const char *dev);

int attach_to_dev(int idx, int prog_fd, const char *dev);
int detach_from_dev(int idx, const char *dev);

int attach_to_dev_tx(int idx, int prog_fd, const char *dev);
int detach_from_dev_tx(int idx, const char *dev);

#endif
