// SPDX-License-Identifier: GPL-2.0
/* Dump users of kvm-nested virt
 *
 * Copyright (c) 2020 David Ahern <dsahern@gmail.com>
 */
#include <linux/bpf.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <locale.h>
#include <bpf/bpf.h>

#include "libbpf_helpers.h"
#include "perf_events.h"
#include "timestamps.h"

#define MAX_CPUS        128

struct data {
	__u64 time;
	__u32 cpu;
};

#include "perf_events.c"

bool done;

static void process_event(struct data *data)
{
	/* nothing to do */
}

static int dump_map(int map_fd)
{
	__u64 *key, *prev_key = NULL, val, pid;
	char buf[64];
	int err;

	key = calloc(1, sizeof(*key));
	if (!key) {
		fprintf(stderr, "Failed to allocate memory for key\n");
		return 1;
	}

	printf("\n%s:\n", timestamp(buf, sizeof(buf), 0));
	while(1) {
		err = bpf_map_get_next_key(map_fd, prev_key, key);
		if (err) {
			if (errno == ENOENT)
				err = 0;
			break;
		}

		val = 0;
		if (!bpf_map_lookup_elem(map_fd, key, &val)) {
			pid = *key;
			printf("    tgid %u pid %u count %llu\n",
				(__u32)(pid >> 32), (__u32)pid, val);
		}

		prev_key = key;
	}

	free(key);
	return err;
}

static void sig_handler(int signo)
{
	printf("Terminating by signal %d\n", signo);
	done = true;
}

static void print_usage(char *prog)
{
	printf(
	"usage: %s OPTS\n\n"
	"	-f bpf-file    bpf filename to load\n"
	"	-t rate        time rate (seconds) to dump stats\n"
	, basename(prog));
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = { };
	char *objfile = "kvm-nested.o";
	struct kprobe_data probes[] = {
		{ .func = "handle_vmresume", .fd = -1 },
	};
	const char *tps[] = {
		"kvm/kvm_nested_vmexit",
		"sched/sched_process_exit",
		NULL
	};
	bool filename_set = false;
	bool use_kprobe = false;
	struct bpf_object *obj;
	int display_rate = 10;
	struct bpf_map *map;
	int rc, tmp;
	int map_fd;

	while ((rc = getopt(argc, argv, "f:t:k")) != -1)
	{
		switch(rc) {
		case 'f':
			objfile = optarg;
			filename_set = true;
			break;
		case 't':
			tmp = atoi(optarg);
			if (!tmp) {
				fprintf(stderr, "Invalid display rate\n");
				return 1;
			}
			display_rate = tmp;
			break;
		case 'k':
			use_kprobe = true;
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		perror("signal");
		return 1;
	}

	setlinebuf(stdout);
	setlinebuf(stderr);

	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
		return 1;

	map = bpf_object__find_map_by_name(obj, "nested_virt_map");
	if (!map) {
		printf("Failed to get map in obj file\n");
		return 1;
	}
	map_fd = bpf_map__fd(map);

	rc = 1;
	if (use_kprobe) {
		if (kprobe_init(obj, probes, ARRAY_SIZE(probes)))
			goto out;
	} else {
		if (do_tracepoint(obj, tps))
			goto out;
	}

	rc = 0;
	while (!done) {
		sleep(display_rate);
		if (dump_map(map_fd))
			break;
	}

out:
	return rc;
}
