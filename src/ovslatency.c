// SPDX-License-Identifier: GPL-2.0
/* Analyze latency of the OVS.
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

#include "ovslatency.h"
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
	__u64 diff[8];
	char buf[64];
	int i;

	/* get difference between samples and save
	 * new sample as old
	 */
	for (i = 0; i < 8; ++i) {
		diff[i] = buckets[i] - prev_buckets[i];

		prev_buckets[i] = buckets[i];
	}

	printf("%s: ", timestamp(buf, sizeof(buf), 0));
	if (diff[7] == 0) {
		printf("No packets\n");
		return;
	}

	printf("total number of packets %llu:\n", diff[7]);
	printf("    time (usec)        count\n");
	printf("       0  - %4u:   %'8llu\n", OVS_BUCKET_0, diff[0]);
	printf("   %4u+  - %4u:   %'8llu\n", OVS_BUCKET_0, OVS_BUCKET_1, diff[1]);
	printf("   %4u+  - %4u:   %'8llu\n", OVS_BUCKET_1, OVS_BUCKET_2, diff[2]);
	printf("   %4u+  - %4u:   %'8llu\n", OVS_BUCKET_2, OVS_BUCKET_3, diff[3]);
	printf("   %4u+  - %4u:   %'8llu\n", OVS_BUCKET_3, OVS_BUCKET_4, diff[4]);
	printf("   %4u+  - %4u:   %'8llu\n", OVS_BUCKET_4, OVS_BUCKET_5, diff[5]);
	printf("   %4u+  -   up:   %'8llu\n", OVS_BUCKET_5, diff[6]);
}

static int ovslat_dump_hist(int hist_map_fd)
{
	static __u64 prev_buckets[8];
	struct ovslat_hist_val val;
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
	struct ovslat_hist_val hist2 = {};
	char *objfile = "ovslatency.o";
	const char *probes[] = {
		"ovs_vport_receive",
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

	map = bpf_object__find_map_by_name(obj, "ovslat_map");
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
		if (ovslat_dump_hist(hist_map_fd))
			break;
	}

	return 0;
}
