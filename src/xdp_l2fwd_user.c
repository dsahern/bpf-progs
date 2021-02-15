/* Copyright (c) 2019-21 David Ahern <dsahern@gmail.com>
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

#include <limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <bpf/bpf.h>

#include "xdp_fdb.h"
#include "str_utils.h"
#include "libbpf_helpers.h"

static bool fdb_map_verify(int map_fd)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	if (bpf_obj_get_info_by_fd(map_fd, &info, &len)) {
		fprintf(stderr, "Failed to get map info: %s: %d",
			strerror(errno), errno);
		return false;
	}

	if (info.type != BPF_MAP_TYPE_HASH ||
	    info.key_size != sizeof(struct fdb_key) ||
	    info.value_size != sizeof(__u32)) {
		fprintf(stderr, "Incompatible map\n");
		return false;
	}

	return true;
}

static bool ports_map_verify(int ports_fd, bool *with_prog)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	if (bpf_obj_get_info_by_fd(ports_fd, &info, &len)) {
		fprintf(stderr, "Failed to get map info: %s: %d",
			strerror(errno), errno);
		return false;
	}

	if (info.value_size == sizeof(struct bpf_devmap_val))
		*with_prog = true;

	if (info.type != BPF_MAP_TYPE_DEVMAP_HASH ||
	    info.key_size != sizeof(__u32) ||
	    (info.value_size != sizeof(__u32) && !with_prog)) {
		fprintf(stderr, "Incompatible map\n");
		return false;
	}

	return true;
}

static int show_entries_cli(int fdb_fd, int ports_fd)
{
	struct fdb_key *key, *prev_key = NULL;
	struct bpf_devmap_val pval;
	bool with_prog = false;
	char buf[IFNAMSIZ];
	int err, i;
	__u32 fval;


	if (!fdb_map_verify(fdb_fd) ||
	    !ports_map_verify(ports_fd, &with_prog))
		return 1;

	key = calloc(1, sizeof(*key));
	if (!key) {
		fprintf(stderr, "Failed to allocate memory for key\n");
		return 1;
	}

	for (i = 0; ; ++i) {
		err = bpf_map_get_next_key(fdb_fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		fval = 0;
		memset(&pval, 0, sizeof(pval));
		if (bpf_map_lookup_elem(fdb_fd, key, &fval))
			goto next_key;

		if (if_indextoname(fval, buf) == NULL) {
			fprintf(stderr, "WARNING: stale device index\n");
			snprintf(buf, IFNAMSIZ, "-");
		}

		printf("-v %u -m ", key->vlan);
		print_mac(key->mac, false);
		printf(" -d %s", buf);

		if (bpf_map_lookup_elem(ports_fd, &fval, &pval)) {
			fprintf(stderr,
				"No ports entry for device %s/%d\n", buf, fval);
			goto end_entry;
		}

		if (with_prog)
			printf(" -p %u", pval.bpf_prog.id);
end_entry:
		printf("\n");
next_key:
		prev_key = key;
	}

	free(key);
	return err;
}

static int show_ports_entries(int map_fd)
{
	__u32 *key, *prev_key = NULL;
	struct bpf_devmap_val val;
	bool with_prog = false;
	int err;

	if (!ports_map_verify(map_fd, &with_prog))
		return 1;

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
			char buf[IFNAMSIZ];

			if (if_indextoname(val.ifindex, buf) == NULL) {
				fprintf(stderr, "WARNING: stale device index\n");
				snprintf(buf, IFNAMSIZ, "-");
			}

			printf("index %u -> device %s/%u",
			       *key, buf, val.ifindex);
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
	int err, i;
	__u32 val;

	if (!fdb_map_verify(map_fd))
		return 1;

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

		val = 0;
		if (!bpf_map_lookup_elem(map_fd, key, &val)) {
			char buf[IFNAMSIZ];

			if (if_indextoname(val, buf) == NULL) {
				fprintf(stderr, "WARNING: stale device index\n");
				snprintf(buf, IFNAMSIZ, "-");
			}

			printf("entry %d: < %u, ", i, key->vlan);
			print_mac(key->mac, false);
			printf(" > --> device %s/%u\n", buf, val);
		}

		prev_key = key;
	}

	free(key);
	return err;
}

/* remove from fdb then remove device */
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
		"    -f id          fdb map id or pinned path\n"
		"    -t id          devmap id or pinned path for tx ports\n"
		"    -d device      device to redirect\n"
		"    -m mac         mac address for entry\n"
		"    -v vlan        vlan for entry\n"
		"    -r             remove entries\n"
		"    -p progid      bpf program id or pinned path to attach to entry\n"
		"    -P             print map entries\n"
		"    -C             print map entries in command line format\n"
		, prog);
}

int main(int argc, char **argv)
{
	struct bpf_devmap_val pval = { .bpf_prog.fd = -1 };
	__u32 fdb_id = 0, ports_id = 0, bpf_prog_id = 0;
	const char *ports_map_path = NULL;
	const char *bpf_prog_path = NULL;
	const char *fdb_map_path = NULL;
	bool print_entries = false;
	struct fdb_key key = {};
	int fdb_fd, ports_fd;
	bool delete = false;
	bool cli_arg = false;
	unsigned long tmp;
	int opt, ret;

	while ((opt = getopt(argc, argv, ":f:t:d:m:v:p:rPC")) != -1) {
		switch (opt) {
		case 'f':
			if (str_to_ulong(optarg, &tmp) == 0) {
				fdb_id = (__u32)tmp;
			} else if (*optarg == '/') {
				fdb_map_path = optarg;
			} else {
				fprintf(stderr, "Invalid fdb map id\n");
				return 1;
			}
			break;
		case 't':
			if (str_to_ulong(optarg, &tmp) == 0) {
				ports_id = (__u32)tmp;
			} else if (*optarg == '/') {
				ports_map_path = optarg;
			} else {
				fprintf(stderr, "Invalid ports map id\n");
				return 1;
			}
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
		case 'p':
			if (str_to_ulong(optarg, &tmp) == 0) {
				bpf_prog_id = (__u32)tmp;
			} else if (*optarg == '/') {
				bpf_prog_path = optarg;
			} else {
				fprintf(stderr, "Invalid program id\n");
				return 1;
			}
			break;
		case 'r':
			delete = true;
			break;
		case 'C':
			cli_arg = true;
			break;
		case 'P':
			print_entries = true;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	fdb_fd = bpf_map_get_fd(fdb_id, fdb_map_path, "fdb_map", "fdb map");
	if (fdb_fd < 0)
		return 1;

	ports_fd = bpf_map_get_fd(ports_id, ports_map_path, "xdp_fwd_ports",
				  "ports map");
	if (ports_fd < 0)
		return 1;

	if (cli_arg)
		return show_entries_cli(fdb_fd, ports_fd);

	if (print_entries) {
		ret = show_fdb_entries(fdb_fd);
		return show_ports_entries(ports_fd) ? : ret;
	}

	pval.bpf_prog.fd = bpf_prog_get_fd(bpf_prog_id, bpf_prog_path, NULL,
					   "redirect program");
	if (pval.bpf_prog.fd < 0)
		return 1;

	if (!pval.ifindex) {
		fprintf(stderr, "Device index not given\n");
		return 1;
	}

	if (delete)
		return remove_entries(fdb_fd, &key, ports_fd, pval.ifindex);

	/* add device to port map and then add fdb entry */
	ret = bpf_map_update_elem(ports_fd, &pval.ifindex, &pval, 0);
	if (ret) {
		fprintf(stderr, "Failed to add ports entry: %s: %d\n",
			strerror(errno), errno);
		remove_entries(fdb_fd, &key, ports_fd, pval.ifindex);
		return ret;
	}

	ret = bpf_map_update_elem(fdb_fd, &key, &pval.ifindex, BPF_ANY);
	if (ret) {
		fprintf(stderr, "Failed to add fdb entry: %s: %d\n",
			strerror(errno), errno);
		remove_entries(fdb_fd, &key, ports_fd, pval.ifindex);
		return ret;
	}

	return 0;
}
