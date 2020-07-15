// SPDX-License-Identifier: GPL-2.0
/* example using ebpf and xdp for ACL
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
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

#include "xdp_acl.h"
#include "libbpf_helpers.h"
#include "str_utils.h"

static int parse_proto(const char *arg, __u8 *proto)
{
	unsigned short p = 0;
	struct protoent *ppe;

	if (*arg == '\0')
		return 0;

	ppe = getprotobyname(arg);
	if (ppe) {
		p = ppe->p_proto;
	} else if (str_to_ushort(arg, &p) != 0 || p > 255) {
		printf("invalid protocol\n");
		return -1;
	}

	*proto = (__u8) p;

	return 0;
}

static int parse_port(const char *arg, __be16 *port)
{
	unsigned short p = 0;


	if (*arg != '\0') {
		if (str_to_ushort(arg, &p) != 0) {
			printf("invalid port\n");
			return -1;
		}
	}

	*port = htons(p);

	return 0;
}

static int parse_addr(const char *arg, struct acl_val *val, bool src)
{
	if (*arg == '\0')
		return 0;

	if (strchr(arg, ':')) {
		struct in6_addr any_in6 = {};
		struct in6_addr in6;

		val->family = AF_INET6;
		if (inet_pton(AF_INET6, arg, &in6) == 0) {
			fprintf(stderr, "Invalid IPv6 address\n");
			return -1;
		}
		if (memcmp(&in6, &any_in6, sizeof(any_in6))) {
			if (src)
				val->saddr.ipv6 = in6;
			else
				val->daddr.ipv6 = in6;
		}
	} else {
		struct in_addr in;

		val->family = AF_INET;
		if (inet_pton(AF_INET, arg, &in) == 0) {
			fprintf(stderr, "Invalid IPv4 address\n");
			return -1;
		}

		if (in.s_addr) {
			if (src)
				val->saddr.ipv4 = in.s_addr;
			else
				val->daddr.ipv4 = in.s_addr;
		}
	}

	return 0;
}

/* acl-spec: proto=...,daddr=...,dport=...,saddr=...,sport=... */
static int handle_acl_entry(const char *_arg, int map_fd)
{
	struct acl_key key = {};
	struct acl_val val = {};
	int nfields, err, i;
	bool delete = false;
	char *fields[7];
	char *arg, *p;

	arg = strdup(_arg);
	if (!arg) {
		err = -ENOMEM;
		goto err_out;
	}

	err = -EINVAL;

	nfields = parsestr(arg, ",", fields, 6);
	if (nfields > 5)
		goto err_out;

	if (*fields[0] == '-') {
		fields[0]++;
		delete = true;
	}
	for (i = 0; i < nfields; ++i) {
		err = 0;
		p = fields[i];
		if (strcmp(p, "ipv4") == 0) {
			val.family = AF_INET;
		} else if (strcmp(p, "ipv6") == 0) {
			val.family = AF_INET6;
		} else if (strncmp(p, "proto=", 6) == 0) {
			p += 6;
			err = parse_proto(p, &key.protocol);
		} else if (strncmp(p, "daddr=", 6) == 0) {
			p += 6;
			err = parse_addr(p, &val, false);
			val.flags |= ACL_FLAG_DADDR_CHECK;
		} else if (strncmp(p, "dport=", 6) == 0) {
			p += 6;
			err = parse_port(p, &key.port);
		} else if (strncmp(p, "sport=", 6) == 0) {
			p += 6;
			err = parse_port(p, &val.port);
		} else if (strncmp(p, "saddr=", 6) == 0) {
			p += 6;
			err = parse_addr(p, &val, true);
			val.flags |= ACL_FLAG_SADDR_CHECK;
		} else {
			printf("unknown keyword\n");
			err = -EINVAL;
		}
		if (err)
			goto err_out;
	}

	if (delete) {
		err = bpf_map_delete_elem(map_fd, &key);
		printf("delete acl entry: %s\n", _arg);
	} else {
		err = bpf_map_update_elem(map_fd, &key, &val, BPF_NOEXIST);
		printf("add acl entry: %s\n", _arg);
	}
err_out:
	if (err)
		fprintf(stderr, "Failed to add acl entry: %s\n", arg);

	free(arg);
	return err ? 1 : 0;
}

static void print_flags(__u8 flags)
{
	if (!flags)
		return;

	printf("    flags:");

	if (flags & ACL_FLAG_SADDR_CHECK)
		printf(" SADDR");

	if (flags & ACL_FLAG_DADDR_CHECK)
		printf(" DADDR");

}

static int print_addr(struct acl_val *val, bool daddr)
{
	struct in6_addr in6;
	struct in_addr in;
	char addrstr[64];
	int n;

	n = printf("%s=", daddr ? "daddr" : "saddr");

	switch(val->family) {
	case AF_INET:
		in.s_addr = daddr ? val->daddr.ipv4 : val->saddr.ipv4;
		n += printf("%s",
			    inet_ntop(AF_INET, &in, addrstr, sizeof(addrstr)));
		break;
	case AF_INET6:
		in6 = daddr ? val->daddr.ipv6 : val->saddr.ipv6;
		n += printf("%s",
			    inet_ntop(AF_INET6, &in6, addrstr, sizeof(addrstr)));
		break;
        }

	return n;
}

static int print_protocol(__u8  protocol)
{
	const char *name;

	switch(protocol) {
	case IPPROTO_ICMP:
		name = "icmp";
		break;
	case IPPROTO_TCP:
		name = "tcp";
		break;
	case IPPROTO_UDP:
		name = "udp";
		break;
	default:
		return printf("%u", protocol);
	}
	return printf("proto=%s", name);
}

static int print_family(__u8 family)
{
	switch(family) {
	case AF_INET:
		return printf("ipv4");
	case AF_INET6:
		return printf("ipv6");
	default:
		return printf("<unknown>");
	}
}

static void dump_entry(struct acl_key *key, struct acl_val *val)
{
	int n = 0;

	if (val->family)
		n += print_family(val->family);

	if (key->protocol) {
		if (n) printf(",");
		n += print_protocol(key->protocol);
	}

	if (val->flags & ACL_FLAG_DADDR_CHECK) {
		if (n) printf(",");
		n += print_addr(val, true);
	}

	if (key->port) {
		if (n) printf(",");
		n += printf("dport=%u", ntohs(key->port));
	}

	if (val->flags & ACL_FLAG_SADDR_CHECK) {
		if (n) printf(",");
		n += print_addr(val, false);
	}

	if (val->port) {
		if (n) printf(",");
		n += printf("sport=%u", ntohs(val->port));
	}

	print_flags(val->flags);

	if (n)
		printf("\n");
}

static int show_acl_entries(int map_fd)
{
	struct bpf_map_info info = {};
	struct acl_key *key, *prev_key;
	struct acl_val val;
	__u32 len;
	int err;

	len = sizeof(info);
	if (bpf_obj_get_info_by_fd(map_fd, &info, &len)) {
		fprintf(stderr, "Failed to get map info: %s: %d",
			strerror(errno), errno);
		return 1;
	}

	if (info.type != BPF_MAP_TYPE_HASH ||
	    info.key_size != sizeof(struct acl_key) ||
	    info.value_size != sizeof(struct acl_val)) {
		fprintf(stderr, "Incompatible map\n");
		return 1;
	}

	key = calloc(1, sizeof(*key));
	if (!key) {
		fprintf(stderr, "Failed to allocate memory for key\n");
		return 1;
	}

	prev_key = NULL;
	while (1) {
		err = bpf_map_get_next_key(map_fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		memset(&val, 0, sizeof(val));
		if (!bpf_map_lookup_elem(map_fd, key, &val))
			dump_entry(key, &val);

		prev_key = key;
	}

	free(key);
	return err;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] -- acl-spec [acl-spec ...]\n"
		"\nOPTS:\n"
		"    -i id          add entry to map with given id\n"
		"    -p path        use map add given path\n"
		"    -P             print acl entries in map\n"
		"\n"
		"acl-spec: [-][ipv4,|ipv6,]proto=...,daddr=...,dport=...,saddr=...,sport=...\n"
		"          if first word starts with '-', rule is deleted\n"
		, prog);
}

int main(int argc, char **argv)
{
	const char *map_path = NULL;
	bool print_entries = false;
	int opt, i, err, ret = 0;
	__u32 map_id = 0;
	int map_fd;

	while ((opt = getopt(argc, argv, ":i:p:P")) != -1) {
		switch (opt) {
		case 'P':
			print_entries = true;
			break;
		case 'p':
			map_path = optarg;
			break;
		case 'i':
			err = atoi(optarg);
			if (!err) {
				fprintf(stderr, "Invalid map id\n");
				return 1;
			}
			map_id = err;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (!map_id && !map_path) {
		fprintf(stderr, "Map id not given\n");
		return 1;
	}

	if (map_id)
		map_fd = bpf_map_get_fd_by_id(map_id);
	else
		map_fd = bpf_map_get_fd_by_path(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get fd for map id: %s: %d\n",
			strerror(errno), errno);
		return 1;
	}

	if (print_entries) {
		ret = show_acl_entries(map_fd);
		goto out;
	}

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	for (i = optind; i < argc; ++i) {
		err = handle_acl_entry(argv[i], map_fd);
		if (err < 0)
			ret = 1;
	}
out:
	close(map_fd);
	return ret;
}
