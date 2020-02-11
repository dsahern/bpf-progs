/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PKTLATENCY_H_
#define _PKTLATENCY_H_

#define MAX_CPUS	128

struct pktlat_ctl {
	u64 ptp_ref;
	u64 mono_ref;
	int ifindex_min;  /* used to ignore packets on eth0, eth1 */
	u32 latency_gen_sample;  /* latency at which a sample is generated */
	u8  gen_samples;  /* send samples to userspace as well as histogram */
};

struct pktlat_hist_key {
	u32 pid;
};

struct pktlat_hist_val {
	/* 0:     0 -   15] - super fast
	 * 1: (  15 -   50] - under load
	 * 2: (  50 -  100]
	 * 3: ( 100 -  200] - typical under light load
	 * 4: ( 200 -  500] - should be rare
	 * 5: ( 500 - 1000] - bad
	 * 6: (1000 -  up ] - really bad
	 * 7: missing timestamp
	 */
	u64 buckets[8];
	u64 avg;    /* 5 second moving average TO-DO */
};

enum event_type {
	EVENT_SAMPLE,
	EVENT_EXIT,
};

struct data {
	u64	time;
	s64	tstamp;
	u32	ifindex;
	u32	pkt_len;
	u32	pid;
	u8	event_type;
	u8	cpu;
	__be16	protocol;
	u8	pkt_data[64];
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
