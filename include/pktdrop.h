/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PKTDROP_H_
#define _PKTDROP_H_

#define MAX_CPUS	128

enum event_type {
	EVENT_SAMPLE,
	EVENT_EXIT,
};

struct data {
	u64	time;
	u64	location;
	u64	netns;
	u8	event_type;
	u8	cpu;
	u8	nr_frags;
	u8	pkt_type;
	u16	gso_size;
	__be16	protocol;
	u32	ifindex;
	u16	vlan_tci;
	__be16	vlan_proto;
	u32	pkt_len;
	u8	pkt_data[64];
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
