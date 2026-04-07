#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "stats.h"
#include "timestamps.h"

static void hist_set_print_bytes(struct stats *s)
{
	int i;

	for (i = 0; i < s->num_buckets - 1; ++i) {
		if (s->ranges[i] >= SIZE_TB(1)) {
			s->ranges_print[i] = (double)s->ranges[i] / SIZE_TB(1);
			s->ranges_unit[i] = "TB";
		} else if (s->ranges[i] >= SIZE_GB(1)) {
			s->ranges_print[i] = (double)s->ranges[i] / SIZE_GB(1);
			s->ranges_unit[i] = "GB";
		} else if (s->ranges[i] >= SIZE_MB(1)) {
			s->ranges_print[i] = (float)s->ranges[i] / SIZE_MB(1);
			s->ranges_unit[i] = "MB";
		} else if (s->ranges[i] >= SIZE_KB(1)) {
			s->ranges_print[i] = (float)s->ranges[i] / SIZE_KB(1);
			s->ranges_unit[i] = "KB";
		} else {
			s->ranges_print[i] = (float)s->ranges[i];
			s->ranges_unit[i] = "B";
		}
	}

	/* last bucket */
	s->ranges_unit[i] = s->ranges_unit[i-1];
}

static void hist_set_print_rate(struct stats *s)
{
	int i;

	for (i = 0; i < s->num_buckets - 1; ++i) {
		if (s->ranges[i] >= SIZE_TB(1)) {
			s->ranges_print[i] = (double)s->ranges[i] / SIZE_TB(1);
			s->ranges_unit[i] = "TB/sec";
		} else if (s->ranges[i] >= SIZE_GB(1)) {
			s->ranges_print[i] = (double)s->ranges[i] / SIZE_GB(1);
			s->ranges_unit[i] = "GB/sec";
		} else if (s->ranges[i] >= SIZE_MB(1)) {
			s->ranges_print[i] = (float)s->ranges[i] / SIZE_MB(1);
			s->ranges_unit[i] = "MB/sec";
		} else if (s->ranges[i] >= SIZE_KB(1)) {
			s->ranges_print[i] = (float)s->ranges[i] / SIZE_KB(1);
			s->ranges_unit[i] = "KB/sec";
		} else {
			s->ranges_print[i] = (float)s->ranges[i];
			s->ranges_unit[i] = "B/sec";
		}
	}

	/* last bucket */
	s->ranges_unit[i] = s->ranges_unit[i-1];
}

static void hist_set_print_nsec(struct stats *s)
{
	int i;

	for (i = 0; i < s->num_buckets - 1; ++i) {
		if (s->ranges[i] >= NSEC_PER_SEC) {
			s->ranges_print[i] = (double)s->ranges[i] / NSEC_PER_SEC;
			s->ranges_unit[i] = "sec";
		} else if (s->ranges[i] >= NSEC_PER_MSEC) {
			s->ranges_print[i] = (double)s->ranges[i] / NSEC_PER_MSEC;
			s->ranges_unit[i] = "msec";
		} else if (s->ranges[i] >= NSEC_PER_USEC) {
			s->ranges_print[i] = (float)s->ranges[i] / NSEC_PER_USEC;
			s->ranges_unit[i] = "usec";
		} else {
			s->ranges_print[i] = (float)s->ranges[i];
			s->ranges_unit[i] = "nsec";
		}
	}

	/* last bucket */
	s->ranges_unit[i] = s->ranges_unit[i-1];
}

/*
 * P-square algorithm for online quantile estimation.
 * Jain & Chlamtac, CACM 28(10), October 1985.
 *
 * Maintains 5 markers whose heights converge to the desired quantile p
 * without storing individual observations.
 */
static void psquare_init(struct psquare *ps, double p)
{
	ps->dn[0] = 0.0;
	ps->dn[1] = p / 2.0;
	ps->dn[2] = p;
	ps->dn[3] = (1.0 + p) / 2.0;
	ps->dn[4] = 1.0;
}

static void psquare_update(struct psquare *ps, double x)
{
	double d, qp;
	int i, k, sign;

	/* collect the first 5 observations */
	if (ps->count < 5) {
		ps->q[ps->count++] = x;
		if (ps->count == 5) {
			double p = ps->dn[2]; /* quantile is stored in dn[2] */

			/* insertion-sort the 5 seed values */
			for (i = 1; i < 5; i++) {
				double key = ps->q[i];
				int j = i - 1;

				while (j >= 0 && ps->q[j] > key) {
					ps->q[j + 1] = ps->q[j];
					j--;
				}
				ps->q[j + 1] = key;
			}
			for (i = 0; i < 5; i++)
				ps->n[i] = i + 1;
			ps->np[0] = 1.0;
			ps->np[1] = 1.0 + 2.0 * p;
			ps->np[2] = 1.0 + 4.0 * p;
			ps->np[3] = 3.0 + 2.0 * p;
			ps->np[4] = 5.0;
		}
		return;
	}

	/* find cell k where x falls */
	if (x < ps->q[0]) {
		ps->q[0] = x;
		k = 0;
	} else if (x < ps->q[1]) {
		k = 0;
	} else if (x < ps->q[2]) {
		k = 1;
	} else if (x < ps->q[3]) {
		k = 2;
	} else if (x <= ps->q[4]) {
		k = 3;
	} else {
		ps->q[4] = x;
		k = 3;
	}

	/* shift positions of markers above k */
	for (i = k + 1; i < 5; i++)
		ps->n[i]++;

	/* advance desired positions */
	for (i = 0; i < 5; i++)
		ps->np[i] += ps->dn[i];

	/* adjust marker heights using parabolic (P²) or linear interpolation */
	for (i = 1; i <= 3; i++) {
		d = ps->np[i] - ps->n[i];
		if ((d >= 1.0 && ps->n[i + 1] - ps->n[i] > 1) ||
		    (d <= -1.0 && ps->n[i - 1] - ps->n[i] < -1)) {
			sign = (d > 0) ? 1 : -1;
			qp = ps->q[i] +
			     (double)sign / (ps->n[i + 1] - ps->n[i - 1]) *
			     ((ps->n[i] - ps->n[i - 1] + sign) *
			      (ps->q[i + 1] - ps->q[i]) / (ps->n[i + 1] - ps->n[i]) +
			      (ps->n[i + 1] - ps->n[i] - sign) *
			      (ps->q[i] - ps->q[i - 1]) / (ps->n[i] - ps->n[i - 1]));
			if (ps->q[i - 1] < qp && qp < ps->q[i + 1])
				ps->q[i] = qp;
			else
				ps->q[i] += (double)sign *
					    (ps->q[i + sign] - ps->q[i]) /
					    (ps->n[i + sign] - ps->n[i]);
			ps->n[i] += sign;
		}
	}
	ps->count++;
}

/* Returns the current quantile estimate; 0 if fewer than 5 samples seen. */
static __u64 psquare_result(const struct psquare *ps)
{
	double v;

	if (ps->count < 5)
		return 0;
	v = ps->q[2];
	return v > 0.0 ? (__u64)v : 0;
}

int stats_init(struct stats *s, __u64 *ranges, __u32 num_buckets, 
	       enum stats_units units)
{
	int i, rc;

	memset(s, 0, sizeof(*s));
	s->units = units;
	s->min = UINT64_MAX;

	if (units == STATS_UNITS_NSEC) {
		s->p_stats = true;
		psquare_init(&s->p50, 0.50);
		psquare_init(&s->p95, 0.95);
		psquare_init(&s->p99, 0.99);
	}

	if (num_buckets) {
		/* + 1 is for values > max range */
		s->num_buckets = num_buckets + 1;

		s->buckets = calloc(num_buckets + 1, sizeof(*s->buckets));
		s->ranges = calloc(num_buckets + 1, sizeof(*s->ranges));
		s->ranges_print = calloc(num_buckets + 1, sizeof(*s->ranges_print));
		s->ranges_unit = calloc(num_buckets + 1, sizeof(*s->ranges_unit));

		if (!s->buckets || !s->ranges ||
		    !s->ranges_print || !s->ranges_unit) {
			rc = -ENOMEM;
			goto err_out;
		}

		s->ranges[0] = ranges[0];
		for (i = 1; i < num_buckets; ++i) {
			if (ranges[i] < ranges[i-1]) {
				rc = -EINVAL;
				goto err_out;
			}

			s->ranges[i] = ranges[i];
		}

		switch (s->units) {
		case STATS_UNITS_BYTES:
			hist_set_print_bytes(s);
			break;
		case STATS_UNITS_BYTES_PER_SEC:
			hist_set_print_rate(s);
			break;
		case STATS_UNITS_NSEC:
			hist_set_print_nsec(s);
			break;
		}
	}

	return 0;
err_out:
	free(s->buckets);
	free(s->ranges);
	free(s->ranges_print);
	free(s->ranges_unit);
	memset(s, 0, sizeof(*s));

	return rc;
}

void stats_cleanup(struct stats *s)
{
	free(s->buckets);
	free(s->ranges);
	free(s->ranges_print);
	free(s->ranges_unit);
	memset(s, 0, sizeof(*s));
}

void stats_update(struct stats *s, __u64 val)
{
	int i;

	if (val < s->min)
		s->min = val;
	if (val > s->max)
		s->max = val;

	s->sum += val;

	if (s->p_stats) {
		psquare_update(&s->p50, (double)val);
		psquare_update(&s->p95, (double)val);
		psquare_update(&s->p99, (double)val);
	}

	s->entries++;

	if (!s->num_buckets)
		return;

	for (i = 0; i < s->num_buckets - 1; ++i) {
		if (val <= s->ranges[i]) {
			s->buckets[i]++;
			return;
		}
	}

	s->buckets[s->num_buckets - 1]++;
}

static void format_stats_val(const struct stats *s, __u64 val, char *buf, size_t len)
{
	switch (s->units) {
	case STATS_UNITS_NSEC:
		if (val >= NSEC_PER_SEC)
			snprintf(buf, len, "%.1f sec", (double)val / NSEC_PER_SEC);
		else if (val >= NSEC_PER_MSEC)
			snprintf(buf, len, "%.1f msec", (double)val / NSEC_PER_MSEC);
		else if (val >= NSEC_PER_USEC)
			snprintf(buf, len, "%.1f usec", (double)val / NSEC_PER_USEC);
		else
			snprintf(buf, len, "%llu nsec", val);
		break;
	case STATS_UNITS_BYTES:
		if (val >= SIZE_GB(1))
			snprintf(buf, len, "%.1f GB", (double)val / SIZE_GB(1));
		else if (val >= SIZE_MB(1))
			snprintf(buf, len, "%.1f MB", (double)val / SIZE_MB(1));
		else if (val >= SIZE_KB(1))
			snprintf(buf, len, "%.1f KB", (double)val / SIZE_KB(1));
		else
			snprintf(buf, len, "%llu B", val);
		break;
	case STATS_UNITS_BYTES_PER_SEC:
		if (val >= SIZE_GB(1))
			snprintf(buf, len, "%.1f GB/sec", (double)val / SIZE_GB(1));
		else if (val >= SIZE_MB(1))
			snprintf(buf, len, "%.1f MB/sec", (double)val / SIZE_MB(1));
		else if (val >= SIZE_KB(1))
			snprintf(buf, len, "%.1f KB/sec", (double)val / SIZE_KB(1));
		else
			snprintf(buf, len, "%llu B/sec", val);
		break;
	}
}

/* normalize to 70 columns) */
#define NORM_HIST_STR(count, total)  ((count) * 100 / total) * 7 / 10

void stats_print(struct stats *s, FILE *fp)
{
	char buf[101];
	__u32 i = 0;
	__u64 n;

	if (s->entries == 1) {
		char min_s[32];

		format_stats_val(s, s->min, min_s, sizeof(min_s));
		fprintf(fp, "1 sample, val %s\n", min_s);
	} else if (s->entries > 1) {
		char min_s[32], max_s[32], avg_s[32];

		format_stats_val(s, s->min, min_s, sizeof(min_s));
		format_stats_val(s, s->max, max_s, sizeof(max_s));
		format_stats_val(s, s->sum / s->entries, avg_s, sizeof(avg_s));
		fprintf(fp, "%llu samples, min %s  avg %s  max %s",
			s->entries, min_s, avg_s, max_s);

		if (s->p_stats) {
			char p50_s[32], p95_s[32], p99_s[32];

			format_stats_val(s, psquare_result(&s->p50), p50_s, sizeof(p50_s));
			format_stats_val(s, psquare_result(&s->p95), p95_s, sizeof(p95_s));
			format_stats_val(s, psquare_result(&s->p99), p99_s, sizeof(p99_s));

			fprintf(fp, "  p50 %s  p95 %s  p99 %s\n", p50_s, p95_s, p99_s);
		}
		fprintf(fp, "\n");
	}

	if (!s->num_buckets)
		return;

	for (i = 0; i < s->num_buckets-1; ++i) {
		n = NORM_HIST_STR(s->buckets[i], s->entries);
		if (n == 0 && s->buckets[i])
			n = 1;
		memset(buf, '%', n);
		buf[n] = '\0';
		fprintf(fp, "%7s %-6s : %s (%llu)\n", "", "", buf, s->buckets[i]);
		fprintf(fp, "%7.1f %-6s :\n", s->ranges_print[i], s->ranges_unit[i]);
	}

	n = NORM_HIST_STR(s->buckets[i], s->entries);
	if (n == 0 && s->buckets[i])
		n = 1;
	memset(buf, '%', n);
	buf[n] = '\0';
	fprintf(fp, "%7s %-6s : %s (%llu)\n", "", "", buf, s->buckets[i]);
}
