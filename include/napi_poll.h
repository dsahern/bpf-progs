/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_NAPI_POLL_H_
#define _NET_NAPI_POLL_H_

#define MAX_CPUS        128

#define NAPI_BUCKETS  9
struct napi_poll_hist {
        __u64 buckets[NAPI_BUCKETS];
};

/* order of arguments from
 * /sys/kernel/debug/tracing/events/napi/napi_poll/format
 * but skipping all of the common fields:
 *
	field:struct napi_struct * napi;	offset:8;	size:8;	signed:0;
	field:__data_loc char[] dev_name;	offset:16;	size:4;	signed:1;
	field:int work;	offset:20;	size:4;	signed:1;
	field:int budget;	offset:24;	size:4;	signed:1;
 */
struct napi_poll_args {
	__u64		unused;

	void		*napi;
	int		data_loc_dev_name;
	int		work;
	int		budget;
};

#endif
