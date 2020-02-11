/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TIMESTAMPS_H
#define __TIMESTAMPS_H

#define USEC_PER_SEC    1000000ULL
#define NSEC_PER_SEC    1000000000ULL
#define NSEC_PER_MSEC   1000000ULL
#define NSEC_PER_USEC   1000ULL

#define CLOCK_INVALID -1

static inline unsigned long long ts_to_ull(struct timespec *ts)
{
        return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

static inline struct timeval ns_to_timeval(const __s64 nsec)
{
	struct timeval tv;

	tv.tv_sec = nsec / NSEC_PER_SEC;
	tv.tv_usec = (nsec % NSEC_PER_SEC) / NSEC_PER_USEC;

	return tv;
}

static inline void print_time_msec(unsigned long long nsecs, int width)
{
	unsigned long msecs;
	unsigned long usecs;

	msecs  = nsecs / NSEC_PER_MSEC;
	nsecs -= msecs * NSEC_PER_MSEC;
	usecs  = nsecs / NSEC_PER_USEC;
	printf("  %*lu.%03lu", width, msecs, usecs);
}

/* print nanosecond timestamp as sec.usec */
static inline void print_time_usecs(unsigned long long nsecs)
{
        unsigned long secs, usecs;

        secs = nsecs / NSEC_PER_SEC;
        nsecs -= secs * NSEC_PER_SEC;
        usecs = nsecs / NSEC_PER_USEC;
        printf("%lu.%06lu", secs, usecs);
}

int set_reftime(void);
char *timestamp(char *buf, int len, __u64 stime);

int enable_sw_tstamp(void);
int enable_hw_tstamp(const char *dev);
int disable_hw_tstamp(const char *dev);

clockid_t phc_open(const char *phc);
__u64 get_time_ns(clockid_t clk);
#endif
