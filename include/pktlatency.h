/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PKTLATENCY_H_
#define _PKTLATENCY_H_

#define MAX_CPUS	128

#define PKTLAT_BUCKET_0    25
#define PKTLAT_BUCKET_1    50
#define PKTLAT_BUCKET_2    75
#define PKTLAT_BUCKET_3   100
#define PKTLAT_BUCKET_4   250
#define PKTLAT_BUCKET_5   500
/* bucket 6 is > 5
 * bucket 7 is missing timestamps,
 * bucket 8 is running sum
 */
#define PKTLAT_MAX_BUCKETS 9

struct pktlat_ctl {
	__u64 ptp_ref;
	__u64 mono_ref;
	int ifindex_min;  /* used to ignore packets on eth0, eth1 */
	__u32 latency_gen_sample;  /* latency at which a sample is generated */
	__u8  gen_samples;  /* send samples to userspace as well as histogram */
};

struct pktlat_hist_key {
	__u32 pid;
};

struct pktlat_hist_val {
	__u64 buckets[PKTLAT_MAX_BUCKETS];
};

enum event_type {
	EVENT_SAMPLE,
	EVENT_EXIT,
};

struct data {
	__u64	time;
	__s64	tstamp;
	__u32	ifindex;
	__u32	pkt_len;
	__u32	pid;
	__u8	event_type;
	__u8	cpu;
	__be16	protocol;
	__u8	pkt_data[64];
};

/* order of arguments from
 * /sys/kernel/tracing/events/skb/skb_copy_datagram_iovec/format
 * common fields represented by 'unsigned long long unused;'

	field:const void * skbaddr;	offset:8;	size:8;	signed:0;
	field:int len;	offset:16;	size:4;	signed:1;
 */
struct skb_dg_iov_args {
	unsigned long long unused;

	void *skbaddr;
	int len;
};

/* order of arguments from
 * /sys/kernel/tracing/events/sched/sched_process_exit/format
 * common fields represented by 'unsigned long long unused;'

	field:char comm[16];    offset:8;       size:16;        signed:1;
	field:pid_t pid;        offset:24;      size:4; signed:1;
	field:int prio; offset:28;      size:4; signed:1;
 */
struct sched_exit_args {
	unsigned long long unused;

	char comm[16];
	pid_t pid;
	int prio;
};

#endif
