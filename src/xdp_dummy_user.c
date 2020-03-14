// SPDX-License-Identifier: GPL-2.0
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

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] interface-list\n"
		"\nOPTS:\n"
		"    -d            detach program\n"
		"    -f bpf-file   bpf filename to load\n"
		"    -g            skb mode\n"
		, prog);
}

int main(int argc, char **argv)
{
	int (*attach_fn)(int idx, int prog_fd, const char *dev) = attach_to_dev;
	int (*detach_fn)(int idx, const char *dev) = detach_from_dev;
	struct bpf_prog_load_attr prog_load_attr = { };
	const char *objfile = "xdp_dummy_kern.o";
	const char *pname = "xdp_dummy";
	bool filename_set = false;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int opt, i, prog_fd;
	bool attach = true;
	int ret = 0;

	while ((opt = getopt(argc, argv, ":df:g")) != -1) {
		switch (opt) {
		case 'f':
			objfile = optarg;
			filename_set = true;
			break;
		case 'd':
			attach = false;
			break;
		case 'g':
			attach_fn = attach_to_dev_generic;
			detach_fn = detach_from_dev_generic;
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

	if (!attach) {
		for (i = optind; i < argc; ++i) {
			int idx, err;

			idx = if_nametoindex(argv[i]);
			if (!idx)
				idx = strtoul(argv[i], NULL, 0);

			if (!idx) {
				fprintf(stderr, "Invalid device argument\n");
				return 1;
			}
			err = detach_fn(idx, argv[i]);
			if (err)
				ret = err;
		}
		return ret;
	}

	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
                return 1;

	prog = bpf_object__find_program_by_title(obj, pname);
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		printf("program not found: %s\n", strerror(prog_fd));
		return 1;
	}

	for (i = optind; i < argc; ++i) {
		int idx, err;

		idx = if_nametoindex(argv[i]);
		if (!idx)
			idx = strtoul(argv[i], NULL, 0);

		if (!idx) {
			fprintf(stderr, "Invalid device argument\n");
			return 1;
		}

		err = attach_fn(idx, prog_fd, argv[i]);
		if (err)
			ret = err;
	}

	return ret;
}
