// SPDX-License-Identifier: GPL-2.0
/* Various time related helpers.
 *
 * phc_open code copied from linuxptp.
 * hw timestamp code based on example in
 *    tools/testing/selftests/networking/timestamping/hwtstamp_config.c
 *
 * David Ahern <dsahern@gmail.com>
 */
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <net/if.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "timestamps.h"

static __u64 mono_ref;
static struct timeval tod_ref;

/* convert monotonic clock to realtime */
static void tod_from_mono(__u64 stime, struct timeval *tv_res)
{
	unsigned long long dt;
	struct timeval tv_dt;

	if (stime > mono_ref) {
		dt = stime - mono_ref;
		tv_dt.tv_sec = (time_t) (dt / NSEC_PER_SEC);
		tv_dt.tv_usec = (dt - tv_dt.tv_sec * NSEC_PER_SEC) / 1000;
		timeradd(&tod_ref, &tv_dt, tv_res);
	} else {
		dt = mono_ref - stime;
		tv_dt.tv_sec = (time_t) (dt / NSEC_PER_SEC);
		tv_dt.tv_usec = (dt - tv_dt.tv_sec * NSEC_PER_SEC) / 1000;
		timersub(&tod_ref, &tv_dt, tv_res);
	}
}

char *timestamp(char *buf, int len, __u64 stime)
{
	struct timeval tv;

	buf[0] = '\0';
	if (len < 64)
		return buf;

	if (mono_ref == 0 && stime) {
		unsigned long secs, usecs;
		unsigned long long nsecs;

		nsecs = stime;
		secs = nsecs / NSEC_PER_SEC;
		nsecs -= secs * NSEC_PER_SEC;
		usecs = nsecs / NSEC_PER_USEC;
		snprintf(buf, len, "%5lu.%06lu", secs, usecs);

		return buf;
	}

	if (stime)
		tod_from_mono(stime, &tv);
	else
		gettimeofday(&tv, NULL);

	return timestamp_tv(&tv, buf, len);
}

char *timestamp_tv(const struct timeval *tv, char *buf, int len)
{
	struct tm ltime;

	if (localtime_r(&tv->tv_sec, &ltime) == NULL)
		buf[0] = '\0';
	else {
		char date[64];

		strftime(date, sizeof(date), "%H:%M:%S", &ltime);
		snprintf(buf, len, "%s.%06d", date, (int) tv->tv_usec);
	}

	return buf;
}

__u64 get_time_ns(clockid_t clk)
{
	struct timespec ts;

	if (clock_gettime(clk, &ts) != 0) {
		fprintf(stderr, "clock_gettime(CLOCK_MONOTONIC) failed\n");
		return 0;
	}

	return (__u64)ts_to_ull(&ts);
}

/* used to convert monotonic timestamps to time-of-day.
 * good enough for the purpose at hand
 */
int set_reftime(void)
{
	if (gettimeofday(&tod_ref, NULL) != 0) {
		fprintf(stderr, "gettimeofday failed\n");
		return 1;
	}

	mono_ref = get_time_ns(CLOCK_MONOTONIC);

	return 0;
}

static int tstamp_sd = -1;

/* based on example usage in
 * tools/testing/selftests/networking/timestamping/hwtstamp_config.c
 */
static int do_hw_tstamp(const char *dev, int rx_filter, int tx_type)
{
	unsigned long cmd = SIOCSHWTSTAMP;
	struct hwtstamp_config config = {
		.tx_type = tx_type,
		.rx_filter = rx_filter,
	};
	struct ifreq ifr = {};

	if (tstamp_sd < 1) {
		tstamp_sd = socket(AF_INET, SOCK_DGRAM, 0);
		if (tstamp_sd < 0) {
			fprintf(stderr, "Failed to open ipv4 datagram socket\n");
			return -1;
		}
	}

	strcpy(ifr.ifr_name, dev);
	ifr.ifr_data = (caddr_t)&config;

	if (ioctl(tstamp_sd, cmd, &ifr)) {
		perror("ioctl");
		return 1;
	}

	return 0;
}

int enable_hw_tstamp(const char *dev)
{
	return do_hw_tstamp(dev, HWTSTAMP_FILTER_ALL, HWTSTAMP_TX_OFF);
}

int disable_hw_tstamp(const char *dev)
{
	return do_hw_tstamp(dev, HWTSTAMP_FILTER_NONE, HWTSTAMP_TX_OFF);
}

int enable_sw_tstamp(void)
{
	int val = SOF_TIMESTAMPING_RX_SOFTWARE;

	if (tstamp_sd < 1) {
		tstamp_sd = socket(AF_INET, SOCK_DGRAM, 0);
		if (tstamp_sd < 0) {
			fprintf(stderr, "Failed to open ipv4 datagram socket\n");
			return -1;
		}
	}

	if (setsockopt(tstamp_sd, SOL_SOCKET, SO_TIMESTAMPING,
		       &val, sizeof(val))) {
		fprintf(stderr, "Failed to set SO_TIMESTAMPING socket option\n");
		return 1;
	}

	val = 1;
	if (setsockopt(tstamp_sd, SOL_SOCKET, SO_TIMESTAMPNS,
		       &val, sizeof(val))) {
		fprintf(stderr, "Failed to set SO_TIMESTAMPNS socket option\n");
		return 1;
	}

	return 0;
}

/* copied from linuxptp */

#include <syscall.h>
#include <sys/timex.h>

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)       ((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))

static inline int clock_adjtime(clockid_t id, struct timex *tx)
{
	return syscall(__NR_clock_adjtime, id, tx);
}

clockid_t phc_open(const char *phc)
{
	struct timex tx = {};
	struct timespec ts;
	clockid_t clkid;
	int fd;

	fd = open(phc, O_RDWR);
	if (fd < 0)
		return CLOCK_INVALID;

	clkid = FD_TO_CLOCKID(fd);
	/* check if clkid is valid */
	if (clock_gettime(clkid, &ts)) {
		close(fd);
		return CLOCK_INVALID;
	}

	if (clock_adjtime(clkid, &tx)) {
		close(fd);
		return CLOCK_INVALID;
	}

	return clkid;
}

/* end copied from linuxptp */
