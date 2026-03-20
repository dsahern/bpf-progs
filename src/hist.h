#pragma once

#include <linux/types.h>
#include <stdbool.h>

#define SIZE_B(x)     (x)
#define SIZE_KB(x)   ((x) * 1024ULL)
#define SIZE_MB(x)   ((x) * 1024ULL * 1024ULL)
#define SIZE_GB(x)   ((x) * 1024ULL * 1024ULL * 1024ULL)
#define SIZE_TB(x)   ((x) * 1024ULL * 1024ULL * 1024ULL * 1024ULL)

enum hist_units {
	HIST_UNITS_BYTES,
	HIST_UNITS_BYTES_PER_SEC,
	HIST_UNITS_NSEC,
};

struct hist {
	__u64 entries;
	__u64 *buckets;
	__u64 *ranges;

	float *ranges_print;
	char **ranges_unit;

	__u32 num_buckets;
	enum hist_units units;
};

int hist_init(struct hist *h, __u64 *ranges, __u32 num_buckets,
	      enum hist_units);
void hist_cleanup(struct hist *h);
void hist_update(struct hist *h, __u64 val);
void hist_print(struct hist *h);
