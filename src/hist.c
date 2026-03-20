#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "hist.h"
#include "timestamps.h"

static void hist_set_print_bytes(struct hist *h)
{
	int i;

	for (i = 0; i < h->num_buckets - 1; ++i) {
		if (h->ranges[i] >= SIZE_TB(1)) {
			h->ranges_print[i] = h->ranges[i] / SIZE_TB(1);
			h->ranges_unit[i] = "TB";
		} else if (h->ranges[i] >= SIZE_GB(1)) {
			h->ranges_print[i] = h->ranges[i] / SIZE_GB(1);
			h->ranges_unit[i] = "GB";
		} else if (h->ranges[i] >= SIZE_MB(1)) {
			h->ranges_print[i] = h->ranges[i] / SIZE_MB(1);
			h->ranges_unit[i] = "MB";
		} else if (h->ranges[i] >= SIZE_KB(1)) {
			h->ranges_print[i] = h->ranges[i] / SIZE_KB(1);
			h->ranges_unit[i] = "KB";
		} else {
			h->ranges_print[i] = h->ranges[i];
			h->ranges_unit[i] = "B";
		}
	}

	/* last bucket */
	h->ranges_unit[i] = h->ranges_unit[i-1];
}

static void hist_set_print_rate(struct hist *h)
{
	int i;

	for (i = 0; i < h->num_buckets - 1; ++i) {
		if (h->ranges[i] >= SIZE_TB(1)) {
			h->ranges_print[i] = h->ranges[i] / SIZE_TB(1);
			h->ranges_unit[i] = "TB/sec";
		} else if (h->ranges[i] >= SIZE_GB(1)) {
			h->ranges_print[i] = h->ranges[i] / SIZE_GB(1);
			h->ranges_unit[i] = "GB/sec";
		} else if (h->ranges[i] >= SIZE_MB(1)) {
			h->ranges_print[i] = h->ranges[i] / SIZE_MB(1);
			h->ranges_unit[i] = "MB/sec";
		} else if (h->ranges[i] >= SIZE_KB(1)) {
			h->ranges_print[i] = h->ranges[i] / SIZE_KB(1);
			h->ranges_unit[i] = "KB/sec";
		} else {
			h->ranges_print[i] = h->ranges[i];
			h->ranges_unit[i] = "B/sec";
		}
	}

	/* last bucket */
	h->ranges_unit[i] = h->ranges_unit[i-1];
}

static void hist_set_print_nsec(struct hist *h)
{
	int i;

	for (i = 0; i < h->num_buckets - 1; ++i) {
		if (h->ranges[i] >= NSEC_PER_SEC) {
			h->ranges_print[i] = h->ranges[i] / NSEC_PER_SEC;
			h->ranges_unit[i] = "sec";
		} else if (h->ranges[i] >= NSEC_PER_MSEC) {
			h->ranges_print[i] = h->ranges[i] / NSEC_PER_MSEC;
			h->ranges_unit[i] = "msec";
		} else if (h->ranges[i] >= NSEC_PER_USEC) {
			h->ranges_print[i] = h->ranges[i] / NSEC_PER_USEC;
			h->ranges_unit[i] = "usec";
		} else {
			h->ranges_print[i] = h->ranges[i];
			h->ranges_unit[i] = "nsec";
		}
	}

	/* last bucket */
	h->ranges_unit[i] = h->ranges_unit[i-1];
}

int hist_init(struct hist *h, __u64 *ranges, __u32 num_buckets, 
	      enum hist_units units)
{
	int i, rc;

	if (num_buckets < 1)
		return -EINVAL;

	h->units = units;

	/* + 1 is for values > max range */
	h->num_buckets = num_buckets + 1;

	h->buckets = calloc(num_buckets + 1, sizeof(*h->buckets));
	h->ranges = calloc(num_buckets + 1, sizeof(*h->ranges));
	h->ranges_print = calloc(num_buckets + 1, sizeof(*h->ranges_print));
	h->ranges_unit = calloc(num_buckets + 1, sizeof(*h->ranges_unit));

	if (!h->buckets || !h->ranges ||
	    !h->ranges_print || !h->ranges_unit) {
		rc = -ENOMEM;
		goto err_out;
	}

	h->ranges[0] = ranges[0];
	for (i = 1; i < num_buckets; ++i) {
		if (ranges[i] < ranges[i-1]) {
			rc = -EINVAL;
			goto err_out;
		}

		h->ranges[i] = ranges[i];
	}

	switch (h->units) {
	case HIST_UNITS_BYTES:
		hist_set_print_bytes(h);
		break;
	case HIST_UNITS_BYTES_PER_SEC:
		hist_set_print_rate(h);
		break;
	case HIST_UNITS_NSEC:
		hist_set_print_nsec(h);
		break;
	}

	return 0;
err_out:
	free(h->buckets);
	free(h->ranges);
	free(h->ranges_print);
	free(h->ranges_unit);
	memset(h, 0, sizeof(*h));

	return rc;
}

void hist_cleanup(struct hist *h)
{
	free(h->buckets);
	free(h->ranges);
	free(h->ranges_print);
	free(h->ranges_unit);
	memset(h, 0, sizeof(*h));
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
	__u32 i = 0;

	for (i = 0; i < h->num_buckets-1; ++i) {
		printf("%7s %-6s : %'8llu\n", "", "", h->buckets[i]);
		printf("%7.1f %-6s :\n", h->ranges_print[i], h->ranges_unit[i]);
	}
	printf("%7s %-6s : %'8llu\n", "", "", h->buckets[i]);
}
