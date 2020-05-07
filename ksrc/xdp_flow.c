// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 *
 * Packet parser for xdp context
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

#include "xdp_flow.h"

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

static __always_inline int parse_v6(struct flow *fl, void *nh, void *data_end)
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

	nh += sizeof(*ip6h);
	return parse_transport(fl, nh, data_end);
}

static __always_inline int parse_v4(struct flow *fl, void *nh, void *data_end)
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

	nh += (iph->ihl << 2);
	//nh = iph + 1;
	return parse_transport(fl, nh, data_end);
}

/*
 * rc > 0:  unhandled protocol
 * rc < 0:  error parsing headers
 * rc == 0: all good
 */
static __always_inline int parse_pkt(struct flow *fl, __be16 eth_proto,
				     void *nh, void *data_end)
{
	int rc;

	if (eth_proto == htons(ETH_P_IP))
		rc = parse_v4(fl, nh, data_end);
	else if (eth_proto == htons(ETH_P_IPV6))
		rc = parse_v6(fl, nh, data_end);
	else
		rc = 1;

	return rc;
}
