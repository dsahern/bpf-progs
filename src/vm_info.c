// SPDX-License-Identifier: GPL-2.0
/* Manage VM info map
 *
 * Copyright (c) 2020 David Ahern <dsahern@gmail.com>
 */

#include <linux/bpf.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <bpf/bpf.h>

#include "vm_info.h"
#include "str_utils.h"
#include "libbpf_helpers.h"

static int show_entries(int fd, bool cli_arg)
{
	__u32 *key, *prev_key = NULL;
	struct bpf_map_info info = {};
	struct vm_info val;
	char buf[IFNAMSIZ];
	char v4str[64];
	char v6str[64];
	int err, i;
	__u32 len;

	len = sizeof(info);
	if (bpf_obj_get_info_by_fd(fd, &info, &len)) {
		fprintf(stderr, "Failed to get map info: %s: %d",
			strerror(errno), errno);
		return 1;
	}

	if (info.type != BPF_MAP_TYPE_HASH ||
	    info.key_size != sizeof(__u32) ||
	    info.value_size != sizeof(struct vm_info)) {
		fprintf(stderr, "Incompatible map\n");
		return 1;
	}

	key = calloc(1, sizeof(*key));
	if (!key) {
		fprintf(stderr, "Failed to allocate memory for key\n");
		return 1;
	}

	for (i = 0; ; ++i) {
		err = bpf_map_get_next_key(fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		memset(&val, 0, sizeof(val));
		if (bpf_map_lookup_elem(fd, key, &val))
			goto next_key;


		if (if_indextoname(*key, buf) == NULL) {
			fprintf(stderr, "WARNING: stale device index\n");
			snprintf(buf, IFNAMSIZ, "-");
		}

		inet_ntop(AF_INET, &val.v4addr, v4str, sizeof(v4str));
		inet_ntop(AF_INET6, &val.v6addr, v6str, sizeof(v6str));

		if (cli_arg) {
			printf("    -i %u -d %u -m ", val.vmid, *key);
			print_mac(val.mac, false);
			if (val.vlan_TCI)
				printf(" -v %u", ntohs(val.vlan_TCI));
			printf(" -4 %s -6 %s\n", v4str, v6str);
		} else {
			printf("    device key %u / %s vm %u mac ",
				*key, buf, val.vmid);
			print_mac(val.mac, false);
			if (val.vlan_TCI)
				printf(" vlan %u", ntohs(val.vlan_TCI));
			printf(" v4 %s v6 %s\n", v4str, v6str);
		}
next_key:
		prev_key = key;
	}

	free(key);
	return err;
}

static int remove_entry(int fd, __u32 idx)
{
	int rc;

	rc = bpf_map_delete_elem(fd, &idx);
	if (rc)
		fprintf(stderr, "Failed to delete VM entry\n");

	return rc;
}

static int parse_v6_addr(const char *arg, struct in6_addr *addr)
{
	struct in6_addr any_in6 = {};

        if (*arg == '\0')
                return -1;

	if (inet_pton(AF_INET6, arg, addr) == 0 ||
	    memcmp(addr, &any_in6, sizeof(any_in6)) == 0) {
		fprintf(stderr, "Invalid IPv6 address\n");
		return -1;
	}

	return 0;
}

static int parse_v4_addr(const char *arg, __u32 *addr)
{
	struct in_addr in;

	if (*arg == '\0')
		return -1;

	if (inet_pton(AF_INET, arg, &in) == 0 ||
	    in.s_addr == 0) {
		fprintf(stderr, "Invalid IPv4 address\n");
		return -1;
	}

	*addr = in.s_addr;

        return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS]\n"
		"\nOPTS:\n"
		"    -I id          VM info map id (default: by name vm_info_map)\n"
		"    -i id          VM id\n"
		"    -4 addr        IPv4 network address for VM\n"
		"    -6 addr        IPv6 network address for VM\n"
		"    -m mac         mac address for VM\n"
		"    -d device      tap device for VM\n"
		"    -v vlan        egress vlan tci\n"
		"    -r             remove entry (only device arg needed)\n"
		"    -P             print map entries\n"
		, prog);
}

int main(int argc, char **argv)
{
	__u32 map_id = 0, ifindex = 0;
	bool print_entries = false;
	bool cli_arg = false;
	struct vm_info vi = {};
	bool delete = false;
	unsigned long tmp;
	int fd, opt, ret;

	while ((opt = getopt(argc, argv, ":I:i:4:6:m:v:d:rPC")) != -1) {
		switch (opt) {
		case 'I':
			if (str_to_ulong(optarg, &tmp)) {
				fprintf(stderr, "Invalid map id\n");
				return 1;
			}
			map_id = (__u32)tmp;
			break;
		case 'i':
			if (str_to_ulong(optarg, &tmp)) {
				fprintf(stderr, "Invalid map id\n");
				return 1;
			}
			vi.vmid = (__u32)tmp;
			break;
		case '4':
			if (parse_v4_addr(optarg, &vi.v4addr)) {
				fprintf(stderr, "Invalid IPv4 address\n");
				return 1;
			}
			break;
		case '6':
			if (parse_v6_addr(optarg, &vi.v6addr)) {
				fprintf(stderr, "Invalid IPv4 address\n");
				return 1;
			}
			break;
		case 'm':
			if (str_to_mac(optarg, vi.mac)) {
				fprintf(stderr, "Invalid mac address\n");
				return 1;
			}
			break;
		case 'v':
			if (str_to_int(optarg, 1, 4095, &ret)) {
				fprintf(stderr, "Invalid vlan\n");
				return 1;
			}
			vi.vlan_TCI = htons(ret);
			break;
		case 'd':
			ifindex = if_nametoindex(optarg);
			if (!ifindex) {
				if (str_to_int(optarg, 0, INT_MAX, &ret)) {
					fprintf(stderr, "Invalid device\n");
					return 1;
				}
				ifindex = (__u32)ret;
			}
			break;
		case 'r':
			delete = true;
			break;
		case 'C':
			cli_arg = true;
			/* fallthrough */
		case 'P':
			print_entries = true;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (map_id) {
		fd = bpf_map_get_fd_by_id(map_id);
		if (fd < 0) {
			fprintf(stderr,
				"Failed to get fd for fdb map id, %u: %s: %d\n",
				map_id, strerror(errno), errno);
			return 1;
		}
	} else {
		fd = bpf_map_get_fd_by_name("vm_info_map");
		if (fd < 0) {
			fprintf(stderr, "Failed to get fd for vm_info map: %s: %d\n",
				strerror(errno), errno);
			return 1;
		}
	}

	if (print_entries)
		return show_entries(fd, cli_arg);

	if (!ifindex) {
		fprintf(stderr, "Device index required\n");
		return 1;
	}

	if (delete)
		return remove_entry(fd, ifindex);

	if (!vi.vmid) {
		fprintf(stderr, "VM id required\n");
		return 1;
	}

	/* add device to port map and then add fdb entry */
	ret = bpf_map_update_elem(fd, &ifindex, &vi, BPF_ANY);
	if (ret) {
		fprintf(stderr, "Failed to add VM entry: %s: %d\n",
			strerror(errno), errno);
		return ret;
	}

	return 0;
}
