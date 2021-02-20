#ifndef _FLOW_H_
#define _FLOW_H_
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019-2021 David Ahern <dsahern@gmail.com>
 *
 * Packet parser
 */
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ip.h>

#define ENABLE_FLOW_IPV6

struct flow_ports {
	__be16 sport;
	__be16 dport;
};

struct flow_icmp {
	__u8 type;
	__u8 code;
	__be16 id;
};

#define TCP_FLAG_SYN   1 << 0
#define TCP_FLAG_ACK   1 << 1

/* used for dissecting packets */
struct flow {
	union {
		__u32		ipv4;
#ifdef ENABLE_FLOW_IPV6
		struct in6_addr	ipv6;
#endif
	} saddr;

	union {
		__u32		ipv4;
#ifdef ENABLE_FLOW_IPV6
		struct in6_addr ipv6;
#endif
	} daddr;

	__u8 family;    /* network address family */
	__u8 protocol;  /* L4 protocol */
	__u8 fragment;
	__u8 inner_protocol;
	__u8 tcp_flags;
	__u32 inner_saddr;
	__u32 inner_daddr;

	union {
		struct flow_ports ports;
		struct flow_icmp icmp;
	};
};

#define PARSE_STOP_AT_NET 0x1

#ifdef ENABLE_FLOW_IPV6
static __always_inline int parse_icmp6(struct flow *fl, void *nh,
				       void *data_end)
{
	struct icmp6hdr *icmph = nh;

	if (icmph + 1 > data_end)
		return -1;

	fl->icmp.type = icmph->icmp6_type;
	fl->icmp.code = icmph->icmp6_code;

	switch (icmph->icmp6_type) {
	case ICMPV6_ECHO_REQUEST:
	case ICMPV6_ECHO_REPLY:
		fl->icmp.id = icmph->icmp6_identifier ? : 1;
		break;
	}

	return 0;
}
#endif

static __always_inline int parse_icmp(struct flow *fl, void *nh,
				      void *data_end)
{
	struct icmphdr *icmph = nh;

	if (icmph + 1 > data_end)
		return -1;

	fl->icmp.type = icmph->type;
	fl->icmp.code = icmph->code;

	switch (icmph->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
		fl->icmp.id = icmph->un.echo.id ? : 1;
		break;
	}

	return 0;
}

static __always_inline int parse_udp(struct flow *fl, void *nh,
				     void *data_end)
{
	struct udphdr *uhdr = nh;

	if (uhdr + 1 > data_end)
		return -1;

	fl->ports.sport = uhdr->source;
	fl->ports.dport = uhdr->dest;

	return 0;
}

static __always_inline int parse_tcp(struct flow *fl, void *nh,
				     void *data_end)
{
	struct tcphdr *thdr = nh;

	if (thdr + 1 > data_end)
		return -1;

	fl->ports.sport = thdr->source;
	fl->ports.dport = thdr->dest;

	if (thdr->syn)
		fl->tcp_flags |= TCP_FLAG_SYN;
	if (thdr->ack)
		fl->tcp_flags |= TCP_FLAG_ACK;

	return 0;
}

static __always_inline int parse_transport(struct flow *fl, void *nh,
					   void *data_end)
{
	switch (fl->protocol) {
	case IPPROTO_TCP:
		return parse_tcp(fl, nh, data_end);
	case IPPROTO_UDP:
		return parse_udp(fl, nh, data_end);
	case IPPROTO_ICMP:
		return parse_icmp(fl, nh, data_end);
	case IPPROTO_ICMPV6:
		return parse_icmp6(fl, nh, data_end);
	}
	return 1;
}

#ifdef ENABLE_FLOW_IPV6
static __always_inline int parse_v6(struct flow *fl, void *nh, void *data_end,
				    unsigned int flags)
{
	struct ipv6hdr *ip6h = nh;

	if (ip6h + 1 > data_end)
		return -1;

	if (ip6h->version != 6)
		return -1;

	fl->family = AF_INET6;
	fl->protocol = ip6h->nexthdr;
	fl->saddr.ipv6 = ip6h->saddr;
	fl->daddr.ipv6 = ip6h->daddr;

	if (flags & PARSE_STOP_AT_NET)
		return 0;

	nh += sizeof(*ip6h);
	return parse_transport(fl, nh, data_end);
}
#endif

static __always_inline int parse_v4(struct flow *fl, void *nh, void *data_end,
				    unsigned int flags)
{
	struct iphdr *iph = nh;

	if (iph + 1 > data_end)
		return -1;

	if (iph->version != 4 || iph->ihl < 5)
		return -1;

	fl->family = AF_INET;
	fl->saddr.ipv4 = iph->saddr;
	fl->daddr.ipv4 = iph->daddr;
	fl->protocol = iph->protocol;

	/* fragments won't have the transport header */
	if (ntohs(iph->frag_off) & (IP_MF | IP_OFFSET)) {
		fl->fragment = 1;
		return 0;
	}

	if (flags & PARSE_STOP_AT_NET)
		return 0;

	nh += (iph->ihl << 2);

	if (fl->protocol == IPPROTO_IPIP) {
		iph = nh;

		if (iph + 1 > data_end)
			return -1;

		if (iph->version != 4 || iph->ihl < 5)
			return -1;

		fl->inner_saddr = iph->saddr;
		fl->inner_daddr = iph->daddr;
		fl->inner_protocol = iph->protocol;
		if (ntohs(iph->frag_off) & (IP_MF | IP_OFFSET)) {
			fl->fragment = 1;
			return 0;
		}

		nh += (iph->ihl << 2);
	}
	return parse_transport(fl, nh, data_end);
}

/*
 * rc > 0:  unhandled protocol
 * rc < 0:  error parsing headers
 * rc == 0: all good
 */
static __always_inline int parse_pkt(struct flow *fl, __be16 eth_proto,
				     void *nh, void *data_end,
				     unsigned int flags)
{
	int rc;

	if (eth_proto == htons(ETH_P_IP))
		rc = parse_v4(fl, nh, data_end, flags);
#ifdef ENABLE_FLOW_IPV6
	else if (eth_proto == htons(ETH_P_IPV6))
		rc = parse_v6(fl, nh, data_end, flags);
#endif
	else
		rc = 1;

	return rc;
}
#endif
