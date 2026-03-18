#pragma once

#include <linux/types.h>

struct hist {
	__u64 *buckets;
	__u64 *ranges;
	__u64 entries;
	__u64 print_factor;
	__u32 num_buckets;
};

int hist_init(__u64 *ranges, __u32 num_buckets, struct hist *h, __u64 print_factor);
void hist_update(struct hist *h, __u64 val);
void hist_print(struct hist *h);
