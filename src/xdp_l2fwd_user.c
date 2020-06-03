/* Copyright (c) 2019 David Ahern <dsahern@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_fdb.h"
#include "str_utils.h"

static int short_ports_entries(int map_fd)
{
	__u32 *key, *prev_key = NULL, len;
	struct bpf_map_info info = {};
	bool with_prog = false;
	struct bpf_devmap_val val;
	int err;

	len = sizeof(info);
	if (bpf_obj_get_info_by_fd(map_fd, &info, &len)) {
		fprintf(stderr, "Failed to get map info: %s: %d",
			strerror(errno), errno);
		return 1;
	}

	if (info.value_size == sizeof(val))
		with_prog = true;

	if (info.type != BPF_MAP_TYPE_DEVMAP ||
	    info.key_size != sizeof(__u32) ||
	    (info.value_size != sizeof(__u32) && !with_prog)) {
		fprintf(stderr, "Incompatible map\n");
		return 1;
	}

	key = calloc(1, sizeof(*key));
	if (!key) {
		fprintf(stderr, "Failed to allocate memory for key\n");
		return 1;
	}

	printf("\nPorts map:\n");
	while(1) {
		err = bpf_map_get_next_key(map_fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		memset(&val, 0, sizeof(val));
		if (!bpf_map_lookup_elem(map_fd, key, &val)) {
			printf("index %u -> device %u", *key, val.ifindex);
			if (with_prog && val.bpf_prog.id)
				printf(", prog id %u", val.bpf_prog.id);
			printf("\n");
		}

		prev_key = key;
	}

	free(key);
	return err;
}

static int show_fdb_entries(int map_fd)
{
	struct fdb_key *key, *prev_key = NULL;
	struct bpf_map_info info = {};
	__u32 val, len;
	int err, i;

	len = sizeof(info);
	if (bpf_obj_get_info_by_fd(map_fd, &info, &len)) {
		fprintf(stderr, "Failed to get map info: %s: %d",
			strerror(errno), errno);
		return 1;
	}

	if (info.type != BPF_MAP_TYPE_HASH ||
	    info.key_size != sizeof(struct fdb_key) ||
	    info.value_size != sizeof(__u32)) {
		fprintf(stderr, "Incompatible map\n");
		return 1;
	}

	key = calloc(1, sizeof(*key));
	if (!key) {
		fprintf(stderr, "Failed to allocate memory for key\n");
		return 1;
	}

	printf("FDB map:\n");
	for (i = 0; ; ++i) {
		err = bpf_map_get_next_key(map_fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		memset(&val, 0, sizeof(val));
		if (!bpf_map_lookup_elem(map_fd, key, &val)) {
			printf("entry %d: <", i);
			print_mac(key->mac, false);
			printf(", %u> --> ports index %u\n", key->vlan, val);
		}

		prev_key = key;
	}

	free(key);
	return err;
}

static int remove_entries(int fdb_fd, struct fdb_key *key,
			  int ports_fd, int idx)
{
	int rc;

	rc = bpf_map_delete_elem(fdb_fd, key);
	if (rc)
		fprintf(stderr, "Failed to delete fdb entry\n");

	rc = bpf_map_delete_elem(ports_fd, &idx);
	if (rc)
		fprintf(stderr, "Failed to delete ports entry\n");
	return rc;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS]\n"
		"\nOPTS:\n"
		"    -f id          fdb map id\n"
		"    -t id          devmap id for tx ports\n"
		"    -d device      device to redirect\n"
		"    -m mac         mac address for entry\n"
		"    -v vlan        vlan for entry\n"
		"    -i idx         ports index for fdb map\n"
		"    -r             remove entries\n"
		"    -p progid      bpf program id to attach to entry\n"
		"    -P             print map entries\n"
		, prog);
}

int main(int argc, char **argv)
{
	struct bpf_devmap_val pval = { .bpf_prog.fd = -1 };
	__u32 fdb_id = 0, ports_id = 0, bpf_prog_id = 0;
	bool print_entries = false;
	struct fdb_key key = {};
	int opt, ret, idx = -1;
	int fdb_fd, ports_fd;
	bool delete = false;
	unsigned long tmp;

	while ((opt = getopt(argc, argv, ":f:t:d:m:v:i:p:rP")) != -1) {
		switch (opt) {
		case 'f':
			if (str_to_ulong(optarg, &tmp)) {
				fprintf(stderr, "Invalid map id\n");
				return 1;
			}
			fdb_id = (__u32)tmp;
			break;
		case 't':
			if (str_to_ulong(optarg, &tmp)) {
				fprintf(stderr, "Invalid map id\n");
				return 1;
			}
			ports_id = (__u32)tmp;
			break;
		case 'd':
			pval.ifindex = if_nametoindex(optarg);
			if (!pval.ifindex) {
				if (str_to_int(optarg, 0, INT_MAX, &ret)) {
					fprintf(stderr, "Invalid device\n");
					return 1;
				}
				pval.ifindex = (__u32)ret;
			}
			break;
		case 'm':
			if (str_to_mac(optarg, key.mac)) {
				fprintf(stderr, "Invalid mac address\n");
				return 1;
			}
			break;
		case 'v':
			if (str_to_int(optarg, 0, 4095, &ret)) {
				fprintf(stderr, "Invalid vlan\n");
				return 1;
			}
			key.vlan = (__u16)ret;
			break;
		case 'i':
			if (str_to_int(optarg, 0, 511, &idx)) {
				fprintf(stderr, "Invalid vlan\n");
				return 1;
			}
			break;
		case 'p':
			if (str_to_ulong(optarg, &tmp)) {
				fprintf(stderr, "Invalid program id\n");
				return 1;
			}
			bpf_prog_id = (__u32)tmp;
			break;
		case 'r':
			delete = true;
			break;
		case 'P':
			print_entries = true;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (!fdb_id || !ports_id) {
		fprintf(stderr, "fdb or ports map id not given\n");
		return 1;
	}

	fdb_fd = bpf_map_get_fd_by_id(fdb_id);
	if (fdb_fd < 0) {
		fprintf(stderr, "Failed to get fd for fdb map id, %u: %s: %d\n",
			fdb_id, strerror(errno), errno);
		return 1;
	}

	ports_fd = bpf_map_get_fd_by_id(ports_id);
	if (ports_fd < 0) {
		fprintf(stderr, "Failed to get fd for ports map id, %u: %s: %d\n",
			ports_id, strerror(errno), errno);
		return 1;
	}

	if (print_entries) {
		ret = show_fdb_entries(fdb_fd);
		if (ret)
			return ret;

		return short_ports_entries(ports_fd);
	}

	if (bpf_prog_id) {
		pval.bpf_prog.fd = bpf_prog_get_fd_by_id(bpf_prog_id);
		if (pval.bpf_prog.fd < 0) {
			fprintf(stderr, "Failed to get fd for prog id: %s: %d\n",
				strerror(errno), errno);
			return 1;
		}
	}

	if (!pval.ifindex || idx < 0) {
		fprintf(stderr, "Device or fdb index not given\n");
		return 1;
	}

	if (delete)
		return remove_entries(fdb_fd, &key, ports_fd, idx);

	ret = bpf_map_update_elem(fdb_fd, &key, &idx, BPF_NOEXIST);
	if (ret) {
		fprintf(stderr, "Failed to add fdb entry: %s: %d\n",
			strerror(errno), errno);
		remove_entries(fdb_fd, &key, ports_fd, idx);
		return ret;
	}

	ret = bpf_map_update_elem(ports_fd, &idx, &pval, 0);
	if (ret) {
		fprintf(stderr, "Failed to add ports entry: %s: %d\n",
			strerror(errno), errno);
		remove_entries(fdb_fd, &key, ports_fd, idx);
		return ret;
	}

	return 0;
}
