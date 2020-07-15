// SPDX-License-Identifier: GPL-2.0
/* Example using ebpf at XDP layer for Layer 3 forwarding.
 *
 * Copyright (c) 2017-2020 David Ahern <dsahern@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
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

#include "libbpf_helpers.h"
#include "str_utils.h"

static int do_attach(int idx, int prog_fd, int map_fd, const char *name)
{
	int err;

	err = attach_to_dev(idx, prog_fd, name);
	if (err < 0)
		return err;

	/* Adding ifindex as a possible egress TX port */
	err = bpf_map_update_elem(map_fd, &idx, &idx, 0);
	if (err)
		printf("ERROR: failed using device %s as TX-port\n", name);

	return err;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] interface-list\n"
		"\nOPTS:\n"
		"    -f bpf-file    bpf filename to load\n"
		"    -d             detach program\n"
		"    -D             direct table lookups (skip fib rules)\n",
		prog);
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	const char *objfile = "xdp_l3fwd_kern.o";
	const char *prog_name = "xdp_l3fwd";
	bool filename_set = false;
	struct bpf_program *prog;
	int prog_fd, map_fd = -1;
	struct bpf_object *obj;
	int opt, i, idx, err;
	bool attach = true;
	int ret = 0;

	while ((opt = getopt(argc, argv, ":dDf:")) != -1) {
		switch (opt) {
		case 'f':
			objfile = optarg;
			filename_set = true;
			break;
		case 'd':
			attach = false;
			break;
		case 'D':
			prog_name = "xdp_l3fwd_direct";
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	if (attach) {
		if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
			return 1;

		prog = bpf_object__find_program_by_title(obj, prog_name);
		prog_fd = bpf_program__fd(prog);
		if (prog_fd < 0) {
			printf("program not found: %s\n", strerror(prog_fd));
			return 1;
		}
		map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj,
							"xdp_tx_ports"));
		if (map_fd < 0) {
			printf("map not found: %s\n", strerror(map_fd));
			return 1;
		}
	}

	for (i = optind; i < argc; ++i) {
		idx = get_ifidx(argv[i]);
		if (!idx) {
			fprintf(stderr, "Invalid arg\n");
			return 1;
		}
		if (attach)
			err = do_attach(idx, prog_fd, map_fd, argv[i]);
		else
			err = detach_from_dev(idx, argv[i]);

		if (err)
			ret = err;
	}

	return ret;
}
