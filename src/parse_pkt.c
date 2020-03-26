// SPDX-License-Identifier: GPL-2.0
/* Functions to parse packet and fill in flow struct
 *
 * David Ahern <dsahern@gmail.com>
 */
#include <linux/types.h>
#include <linux/icmpv6.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "flow.h"

#define NDISC_ROUTER_SOLICITATION       133
#define NDISC_ROUTER_ADVERTISEMENT      134
#define NDISC_NEIGHBOUR_SOLICITATION    135
#define NDISC_NEIGHBOUR_ADVERTISEMENT   136

static int parse_tcp(struct flow_tcp *fl_tcp, const __u8 *data, __u32 len)
{
	const struct tcphdr *tcph;

	if (len < sizeof(*tcph))
		return -1;

	tcph = (struct tcphdr *)data;

	fl_tcp->sport = ntohs(tcph->source);
	fl_tcp->dport = ntohs(tcph->dest);

	if (tcph->syn)
		fl_tcp->syn = 1;
	if (tcph->ack)
		fl_tcp->ack = 1;
	if (tcph->fin)
		fl_tcp->fin = 1;
	if (tcph->rst)
		fl_tcp->rst = 1;

	return 0;
}

static int parse_udp(struct flow_udp *fl_udp, const __u8 *data, __u32 len)
{
	const struct udphdr *udph;

	if (len < sizeof(*udph))
		return -1;

	udph = (struct udphdr *)data;

	fl_udp->sport = ntohs(udph->source);
	fl_udp->dport = ntohs(udph->dest);

	return 0;
}

static int parse_icmpv6(struct flow_icmp6 *fli, const __u8 *data, __u32 len)
{
	const struct icmp6hdr *icmp6;

	if (len < sizeof(*icmp6))
		return -1;

	icmp6 = (const struct icmp6hdr *)data;
	fli->icmp6_type = icmp6->icmp6_type;
	fli->icmp6_code = icmp6->icmp6_code;

	return 0;
}

static int parse_transport(struct flow_transport *flt,
			   const __u8 *data, __u32 len)
{

	switch(flt->proto) {
	case IPPROTO_TCP:
		return parse_tcp(&flt->tcp, data, len);
	case IPPROTO_UDP:
		return parse_udp(&flt->udp, data, len);
	case IPPROTO_ICMPV6:
		return parse_icmpv6(&flt->icmp6, data, len);
	}

	return 0;
}

static int parse_ipv6(struct flow_ip6 *fl6, const __u8 *data, __u32 len)
{
	const struct ipv6hdr *ip6h = (const struct ipv6hdr *)data;

	if (len < sizeof(*ip6h))
		return -1;

	fl6->saddr = ip6h->saddr;
	fl6->daddr = ip6h->daddr;
	fl6->trans.proto = ip6h->nexthdr;

	len -= sizeof(*ip6h);
	data += sizeof(*ip6h);

	return parse_transport(&fl6->trans, data, len);
}

static int parse_ipv4(struct flow_ip4 *fl4, const __u8 *data, __u32 len)
{
	const struct iphdr *iph = (const struct iphdr *)data;
	unsigned int hlen;

	if (len < sizeof(*iph))
		return -1;

	fl4->saddr = iph->saddr;
	fl4->daddr = iph->daddr;
	fl4->trans.proto = iph->protocol;

	hlen = iph->ihl << 2;
	len -= hlen;
	data += hlen;

	return parse_transport(&fl4->trans, data, len);
}

static int parse_arp(struct flow_arp *fla, const __u8 *data, __u32 len)
{
	const struct arphdr *arph = (const struct arphdr *)data;
	struct arpdata *arp_data;

	if (len < sizeof(*arph))
		return -1;

	if (ntohs(arph->ar_hrd) != ARPHRD_ETHER || arph->ar_hln != ETH_ALEN ||
	    arph->ar_pro != htons(ETH_P_IP) || arph->ar_pln != 4)
		return -1;

	fla->op = ntohs(arph->ar_op);

	len -= sizeof(*arph);
	if (len < sizeof(*arp_data))
		return -1;

	arp_data = (struct arpdata *)(arph + 1);
	memcpy(&fla->data, arp_data, sizeof(fla->data));

	return 0;
}

int parse_pkt(struct flow *flow, __u8 protocol, const __u8 *data, int len)
{
	const struct ethhdr *eth = (const struct ethhdr *)data;
	__u16 proto = ntohs(eth->h_proto);
	unsigned int hlen = sizeof(*eth);

	if (len < hlen)
		return -1;

	memcpy(flow->dmac, eth->h_dest, ETH_ALEN);
	memcpy(flow->smac, eth->h_source, ETH_ALEN);

	if (proto == ETH_P_8021Q) {
		const struct vlan_hdr *vhdr;

		vhdr = (const struct vlan_hdr *)(data + sizeof(*eth));

		hlen += sizeof(struct vlan_hdr);
		if (len < hlen)
			return -1;

		flow->has_vlan = true;
		flow->vlan.outer_vlan_TCI = ntohs(vhdr->h_vlan_TCI);
		proto = ntohs(vhdr->h_vlan_encapsulated_proto);
	}

	data += hlen;
	len -= hlen;

	flow->proto = proto;
	switch(proto) {
	case ETH_P_ARP:
		return parse_arp(&flow->arp, data, len);
	case ETH_P_IP:
		return parse_ipv4(&flow->ip4, data, len);
	case ETH_P_IPV6:
		return parse_ipv6(&flow->ip6, data, len);
	}

	return 0;
}

static int reverse_transport(const struct flow_transport *fl1,
			     const struct flow_transport *fl2)
{
	if (fl1->proto != fl2->proto)
		return -1;

	switch(fl1->proto) {
	case IPPROTO_TCP:
		if (fl1->tcp.sport != fl2->tcp.dport ||
		    fl1->tcp.dport != fl2->tcp.sport)
			return -1;
		break;
	case IPPROTO_UDP:
		if (fl1->udp.sport != fl2->udp.dport ||
		    fl1->udp.dport != fl2->udp.sport)
			return -1;
		break;
	default:
		return -1;
	}

	return 0;
}

static int reverse_ipv6(const struct flow_ip6 *fl1, const struct flow_ip6 *fl2)
{
	if (memcmp(&fl1->saddr, &fl2->daddr, sizeof(fl1->saddr)) ||
	    memcmp(&fl1->daddr, &fl2->saddr, sizeof(fl1->daddr)))
		return -1;

	return reverse_transport(&fl1->trans, &fl2->trans);
}

static int reverse_ipv4(const struct flow_ip4 *fl1, const struct flow_ip4 *fl2)
{
	if (fl1->saddr != fl2->daddr || fl1->daddr == fl2->saddr)
		return -1;

	return reverse_transport(&fl1->trans, &fl2->trans);
}

int cmp_flow_reverse(const struct flow *fl1, const struct flow *fl2)
{
	if (fl1->proto != fl2->proto)
		return -1;

	switch(fl1->proto) {
	case ETH_P_IP:
		return reverse_ipv4(&fl1->ip4, &fl2->ip4);
	case ETH_P_IPV6:
		return reverse_ipv6(&fl1->ip6, &fl2->ip6);
	}

	return -1;
}

int cmp_flow(const struct flow *fl1, const struct flow *fl2)
{
	return memcmp(fl1, fl2, sizeof(*fl1));
}
