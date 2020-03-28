// SPDX-License-Identifier: GPL-2.0
/* Analyze time to run net_rx_action
 *
 * Copyright (c) 2020 David Ahern <dsahern@gmail.com>
 */
#include <linux/bpf.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>
#include <bpf/bpf.h>

#include "net_rx_action.h"
#include "libbpf_helpers.h"
#include "perf_events.h"
#include "timestamps.h"

struct data {
	__u64 time;
	__u32 cpu;
};

#include "perf_events.c"

static void process_event(struct data *data)
{
	/* nothing to do */
}

static void dump_buckets(__u64 *buckets, __u64 *prev_buckets)
{
	__u64 diff[NET_RX_NUM_BKTS];
	char buf[64];
	int i;

	/* get difference between samples and save
	 * new sample as old
	 */
	for (i = 0; i < NET_RX_NUM_BKTS; ++i) {
		diff[i] = buckets[i] - prev_buckets[i];

		prev_buckets[i] = buckets[i];
	}

	printf("%s: ", timestamp(buf, sizeof(buf), 0));
	printf("errors: %llu\n", diff[NET_RX_ERR_BKT]);
	printf("          time (usec)        count\n");
	printf("         0   - %7u:   %'8llu\n", NET_RX_BUCKET_0, diff[0]);
	printf("   %7u+  - %7u:   %'8llu\n", NET_RX_BUCKET_0, NET_RX_BUCKET_1, diff[1]);
	printf("   %7u+  - %7u:   %'8llu\n", NET_RX_BUCKET_1, NET_RX_BUCKET_2, diff[2]);
	printf("   %7u+  - %7u:   %'8llu\n", NET_RX_BUCKET_2, NET_RX_BUCKET_3, diff[3]);
	printf("   %7u+  - %7u:   %'8llu\n", NET_RX_BUCKET_3, NET_RX_BUCKET_4, diff[4]);
	printf("   %7u+  - %7u:   %'8llu\n", NET_RX_BUCKET_4, NET_RX_BUCKET_5, diff[5]);
	printf("   %7u+  - %7u:   %'8llu\n", NET_RX_BUCKET_5, NET_RX_BUCKET_6, diff[6]);
	printf("   %7u+  - %7u:   %'8llu\n", NET_RX_BUCKET_6, NET_RX_BUCKET_7, diff[7]);
	printf("   %7u+  - %7u:   %'8llu\n", NET_RX_BUCKET_7, NET_RX_BUCKET_8, diff[8]);
	printf("   %7u+  -      up:   %'8llu\n", NET_RX_BUCKET_8, diff[9]);
}

static int net_rx_dump_hist(int hist_map_fd)
{
	static __u64 prev_buckets[NET_RX_NUM_BKTS];
	struct net_rx_hist_val val;
	__u32 idx = 0;

	if (bpf_map_lookup_elem(hist_map_fd, &idx, &val)) {
		fprintf(stderr, "Failed to get hist values\n");
		return 1;
	}

	dump_buckets(val.buckets, prev_buckets);
	printf("\n");

	return 0;
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
	struct net_rx_hist_val hist2 = {};
	char *objfile = "net_rx_action.o";
	const char *probes[] = {
		"net_rx_action",
		NULL,
	};
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

	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
		return 1;

	if (do_kprobe(obj, probes, 0) || do_kprobe(obj, probes, 1))
		return 1;

	map = bpf_object__find_map_by_name(obj, "net_rx_map");
	if (!map) {
		printf("Failed to get histogram map in obj file\n");
		return 1;
	}
	hist_map_fd = bpf_map__fd(map);

	/* make sure index 0 entry exists */
	bpf_map_update_elem(hist_map_fd, &idx, &hist2, BPF_ANY);

	setlinebuf(stdout);
	setlinebuf(stderr);

	while(1) {
		sleep(display_rate);
		if (net_rx_dump_hist(hist_map_fd))
			break;
	}

	return 0;
}
