#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "hist.h"

int hist_init(__u64 *ranges, __u32 num_buckets, struct hist *h, __u64 print_factor)
{
	int i;

	if (num_buckets < 1)
		return -EINVAL;

	/* must be 1 or higher */
	h->print_factor = print_factor ? : 1;

	/* + 1 is for values > max range */
	h->num_buckets = num_buckets + 1;

	h->buckets = calloc(num_buckets + 1, sizeof(__u64));
	h->ranges = calloc(num_buckets + 1, sizeof(__u64));

	if (!h->buckets || !h->ranges) {
		free(h->buckets);
		free(h->ranges);
		h->num_buckets = 0;
		return -ENOMEM;
	}

	h->ranges[0] = ranges[0];
	for (i = 1; i < num_buckets; ++i) {
		if (ranges[i] < ranges[i-1]) {
			free(h->buckets);
			free(h->ranges);
			h->buckets = NULL;
			h->ranges = NULL;
			h->num_buckets = 0;

			return -EINVAL;
		}

		h->ranges[i] = ranges[i];
	}

	return 0;
}

void hist_update(struct hist *h, __u64 val)
{
	int i;

	h->entries++;

	for (i = 0; i < h->num_buckets - 1; ++i) {
		if (val <= h->ranges[i]) {
			h->buckets[i]++;
			return;
		}
	}

	h->buckets[h->num_buckets - 1]++;
}

void hist_print(struct hist *h)
{
	__u64 rl, rh;
	__u32 i;

	rl = h->ranges[0];
	if (h->print_factor > 1)
		rl /= h->print_factor;

	printf("   %'10llu  -> %'10llu:   %'8llu\n", 0ULL, rl, h->buckets[0]);

	for (i = 1; i < h->num_buckets - 1; ++i) {
		rh = h->ranges[i];
		if (h->print_factor > 1)
			rh /= h->print_factor;

		printf("   %'10llu+ -> %'10llu:   %'8llu\n", rl, rh, h->buckets[i]);
		rl = rh;
	}

	printf("   %'10llu+ -> %10s:   %'8llu\n", rl, "up", h->buckets[i]);
}
