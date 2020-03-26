/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FLOW_H_
#define _FLOW_H_

#include <linux/if_ether.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#define NDISC_ROUTER_SOLICITATION       133
#define NDISC_ROUTER_ADVERTISEMENT      134
#define NDISC_NEIGHBOUR_SOLICITATION    135
#define NDISC_NEIGHBOUR_ADVERTISEMENT   136

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define IPPROTO_VRRP 112

#ifndef ETH_P_LLDP
#define ETH_P_LLDP      0x88CC          /* Link Layer Discovery Protocol */
#endif

/* from linux/if_vlan.h */
#define VLAN_PRIO_MASK          0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT         13
#define VLAN_VID_MASK           0x0fff /* VLAN Identifier */

struct vlan_hdr {
	__be16  h_vlan_TCI;
	__be16  h_vlan_encapsulated_proto;
};

struct arpdata {
	__u8 ar_sha[ETH_ALEN];
	__u8 ar_sip[4];
	__u8 ar_tha[ETH_ALEN];
	__u8 ar_tip[4];
};

/* not handling Q-in-Q at the moment */
struct flow_vlan {
	__u16	outer_vlan_TCI;
};

struct flow_arp {
	__u16		op;
	struct arpdata	data;
};

struct flow_tcp {
	__u16	sport;
	__u16	dport;
	bool	fin;
	bool	syn;
	bool	rst;
	bool	ack;
};

struct flow_udp {
	__u16	sport;
	__u16	dport;
};

struct flow_icmp6 {
	__u8 icmp6_type;
	__u8 icmp6_code;
};

struct flow_transport {
	__u8 proto;

	union {
		struct flow_tcp tcp;
		struct flow_udp udp;
		struct flow_icmp6 icmp6;
	};
};

struct flow_ip4 {
	__u32 saddr;
	__u32 daddr;
	struct flow_transport trans;
};

struct flow_ip6 {
	struct in6_addr saddr;
	struct in6_addr daddr;
	struct flow_transport trans;
};

struct flow {
	/* only interested in ethernet frames */
	__u8 dmac[ETH_ALEN];
	__u8 smac[ETH_ALEN];
	__u16 proto;  /* network protocol */

	bool has_vlan;

	struct flow_vlan vlan;

	union {
		struct flow_arp arp;
		struct flow_ip4 ip4;
		struct flow_ip6 ip6;
	};
};

int parse_pkt(struct flow *flow, __u8 protocol, const __u8 *data, int len);
void print_flow(const struct flow *fl);
void print_pkt(__u16 protocol, const __u8 *data, int len);
int cmp_flow(const struct flow *fl1, const struct flow *fl2);
int cmp_flow_reverse(const struct flow *fl1, const struct flow *fl2);

#endif
