/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PKTDROP_H_
#define _PKTDROP_H_

#define MAX_CPUS	128

enum event_type {
	EVENT_SAMPLE,
	EVENT_EXIT,
};

struct data {
	__u64	time;
	__u64	location;
	__u64	netns;
	__u8	event_type;
	__u8	cpu;
	__u8	nr_frags;
	__u8	pkt_type;
	__u16	gso_size;
	__be16	protocol;
	__u32	ifindex;
	__u16	vlan_tci;
	__be16	vlan_proto;
	__u32	pkt_len;
	__u8	pkt_data[64];
};

/* order of arguments from
 * /sys/kernel/tracing/events/skb/kfree_skb/format
 * common fields represented by 'unsigned long long unused;'

 	field:void * skbaddr;	offset:8;	size:8;	signed:0;
	field:void * location;	offset:16;	size:8;	signed:0;
	field:unsigned short protocol;	offset:24;	size:2;	signed:0;
 */
struct kfree_skb_args {
	unsigned long long unused;

	void *skbaddr;
	void *location;
	unsigned short protocol;
};

#endif
