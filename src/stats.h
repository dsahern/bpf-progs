#pragma once

#include <linux/types.h>
#include <stdbool.h>

#define SIZE_B(x)     (x)
#define SIZE_KB(x)   ((x) * 1024ULL)
#define SIZE_MB(x)   ((x) * 1024ULL * 1024ULL)
#define SIZE_GB(x)   ((x) * 1024ULL * 1024ULL * 1024ULL)
#define SIZE_TB(x)   ((x) * 1024ULL * 1024ULL * 1024ULL * 1024ULL)

enum stats_units {
	STATS_UNITS_BYTES,
	STATS_UNITS_BYTES_PER_SEC,
	STATS_UNITS_NSEC,
};

/*
 * P-square algorithm state for online quantile estimation.
 * Maintains 5 markers that track the desired quantile without storing samples.
 */
struct psquare {
	double q[5];    /* marker heights (quantile estimates) */
	double np[5];   /* desired marker positions */
	double dn[5];   /* per-observation increment in desired positions */
	int    n[5];    /* actual marker positions */
	int    count;   /* number of observations processed */
};

struct stats {
	__u64 entries;
	__u64 min;
	__u64 max;
	__u64 sum;

	bool p_stats;
	struct psquare p50;
	struct psquare p95;
	struct psquare p99;

	__u64 *buckets;
	__u64 *ranges;

	float *ranges_print;
	char **ranges_unit;

	__u32 num_buckets;
	enum stats_units units;
};

int stats_init(struct stats *h, __u64 *ranges, __u32 num_buckets,
	       enum stats_units);
void stats_cleanup(struct stats *h);
void stats_update(struct stats *h, __u64 val);
void stats_print(struct stats *h, FILE *fp);
