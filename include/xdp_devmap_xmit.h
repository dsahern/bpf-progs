/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DEVMAP_XMIT_H_
#define _DEVMAP_XMIT_H_

#define MAX_CPUS        128

#define DEVMAP_BUCKETS 10
struct devmap_xmit_hist {
        __u64 buckets[DEVMAP_BUCKETS];
};

/* order of arguments from
 * /sys/kernel/debug/tracing/events/napi/devmap_xmit/format
 * but skipping all of the common fields:
 *
	field:int from_ifindex;	offset:8;	size:4;	signed:1;
	field:u32 act;	offset:12;	size:4;	signed:0;
	field:int to_ifindex;	offset:16;	size:4;	signed:1;
	field:int drops;	offset:20;	size:4;	signed:1;
	field:int sent;	offset:24;	size:4;	signed:1;
	field:int err;	offset:28;	size:4;	signed:1;
 */
struct devmap_xmit_args {
	__u64		unused;

	int from_ifindex;
	__u32 act;
	int to_ifindex;
	int drops;
	int sent;
	int err;
};

#endif
