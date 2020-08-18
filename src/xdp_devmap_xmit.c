// SPDX-License-Identifier: GPL-2.0
/* Analyze latency of the OVS.
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

#include "xdp_devmap_xmit.h"
#include "libbpf_helpers.h"
#include "perf_events.h"
#include "timestamps.h"

struct data {
	__u64 time;
	__u32 cpu;
};

static bool done;

#include "perf_events.c"

static void process_event(struct data *data)
{
	/* nothing to do */
}

static void dump_buckets(__u64 *buckets, __u64 *prev_buckets)
{
	__u64 diff[DEVMAP_BUCKETS];
	char buf[64];
	int i;

	/* get difference between samples and save
	 * new sample as old
	 */
	for (i = 0; i < DEVMAP_BUCKETS; ++i) {
		diff[i] = buckets[i] - prev_buckets[i];
		prev_buckets[i] = buckets[i];
	}

	printf("%s: ", timestamp(buf, sizeof(buf), 0));
	printf("Batching per xdp devmap xmit\n");
	printf("        0:   %'8llu\n", diff[0]);
	printf("        1:   %'8llu\n", diff[1]);
	printf("        2:   %'8llu\n", diff[2]);
	printf("      3-4:   %'8llu\n", diff[3]);
	printf("      5-8:   %'8llu\n", diff[4]);
	printf("     9-15:   %'8llu\n", diff[5]);
	printf("       16:   %'8llu\n", diff[6]);
	printf("    17-32:   %'8llu\n", diff[7]);
	printf("    33-63:   %'8llu\n", diff[8]);
	printf("       64:   %'8llu\n", diff[9]);
}

static int devmap_xmit_dump_hist(int hist_map_fd)
{
	static __u64 prev_buckets[DEVMAP_BUCKETS];
	struct devmap_xmit_hist val;
	__u32 idx = 0;

	if (bpf_map_lookup_elem(hist_map_fd, &idx, &val)) {
		fprintf(stderr, "Failed to get hist values\n");
		return 1;
	}

	dump_buckets(val.buckets, prev_buckets);
	printf("\n");

	return 0;
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
	const char *tps[] = {
		"xdp/xdp_devmap_xmit",
		NULL
	};
	struct devmap_xmit_hist hist = {};
	char *objfile = "xdp_devmap_xmit.o";
	bool filename_set = false;
	struct bpf_object *obj;
	int display_rate = 10;
	struct bpf_map *map;
	int hist_map_fd;
	__u32 idx = 0;
	int rc, tmp;

	while ((rc = getopt(argc, argv, "f:t:")) != -1)
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
	setlocale(LC_NUMERIC, "en_US.utf-8");

	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
		return 1;

	map = bpf_object__find_map_by_name(obj, "devmap_xmit_map");
	if (!map) {
		printf("Failed to get histogram map in obj file\n");
		return 1;
	}
	hist_map_fd = bpf_map__fd(map);

	/* make sure index 0 entry exists */
	bpf_map_update_elem(hist_map_fd, &idx, &hist, BPF_ANY);

	if (do_tracepoint(obj, tps))
		return 1;

	while (!done) {
		sleep(display_rate);
		if (devmap_xmit_dump_hist(hist_map_fd))
			break;
	}

	return 0;
}
