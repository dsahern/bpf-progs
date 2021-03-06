// SPDX-License-Identifier: GPL-2.0
/* Functions to pretty print packet headers
 *
 * David Ahern <dsahern@gmail.com>
 */
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "flow.h"
#include "str_utils.h"

static void print_tcp(const struct flow_tcp *fl, const char *src,
		      const char *dst)
{
	printf("  src=%s/%d -> dst=%s/%d TCP",
		src, fl->sport, dst, fl->dport);

	if (fl->syn)
		printf(" SYN");
	if (fl->ack)
		printf(" ACK");
	if (fl->fin)
		printf(" FIN");
	if (fl->rst)
		printf(" RST");

	printf("\n");
}

static void print_udp(const struct flow_udp *fl, const char *src,
		      const char *dst)
{
	printf("  src=%s/%d -> dst=%s/%d UDP\n",
		src, fl->sport, dst, fl->dport);
}

static void print_icmp6(const struct flow_icmp6 *fli, const char *src,
			const char *dst)
{
	printf("  src=%s -> dst=%s ICMP ", src, dst);
	switch(fli->icmp6_type) {
	case NDISC_ROUTER_SOLICITATION:
		printf("router solicitation\n");
		break;
	case NDISC_ROUTER_ADVERTISEMENT:
		printf("router advertisement\n");
		break;
	case NDISC_NEIGHBOUR_SOLICITATION:
		printf("neighbor solicitation\n");
		break;
	case NDISC_NEIGHBOUR_ADVERTISEMENT:
		printf("neighbor advertisement\n");
		break;
	case ICMPV6_ECHO_REQUEST:
		printf("echo request\n");
		break;
	case ICMPV6_ECHO_REPLY:
		printf("echo reply\n");
		break;
	default:
		printf("unknown %u/%u\n", fli->icmp6_type, fli->icmp6_code);
	}
}

static void print_transport(const struct flow_transport *fl,
			    const char *src, const char *dst)
{
	switch(fl->proto) {
	case IPPROTO_TCP:
		print_tcp(&fl->tcp, src, dst);
		break;
	case IPPROTO_UDP:
		print_udp(&fl->udp, src, dst);
		break;
	case IPPROTO_VRRP:
		printf("    VRRP: src=%s -> dst=%s\n", src, dst);
		break;
	case IPPROTO_ICMPV6:
		print_icmp6(&fl->icmp6, src, dst);
		break;
	default:
		printf("    protocol %u: src=%s -> dst=%s\n",
			fl->proto, src, dst);
	}
}

static void print_ipv6(const struct flow_ip6 *fl6)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &fl6->saddr, src, sizeof(src));
	inet_ntop(AF_INET6, &fl6->daddr, dst, sizeof(dst));

	print_transport(&fl6->trans, src, dst);
}

static void print_ipv4(const struct flow_ip4 *fl4)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &fl4->saddr, src, sizeof(src));
	inet_ntop(AF_INET, &fl4->daddr, dst, sizeof(dst));

	print_transport(&fl4->trans, src, dst);
}

static void print_arphdr(const struct flow_arp *fla)
{
	char addr[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &fla->data.ar_sip, addr, sizeof(addr));
	printf("sender: %s ", addr);
	print_mac(fla->data.ar_sha, false);

	inet_ntop(AF_INET, &fla->data.ar_tip, addr, sizeof(addr));
	printf(" target: %s ", addr);
	print_mac(fla->data.ar_tha, false);
}

static void print_arp(const struct flow_arp *fla)
{
	printf("    ");

	switch(fla->op) {
	case ARPOP_REQUEST:
		printf("arp request: ");
		break;
	case ARPOP_REPLY:
		printf("arp reply: ");
		break;
	case ARPOP_RREQUEST:
		printf("rarp request: ");
		break;
	case ARPOP_RREPLY:
		printf("rarp reply: ");
		break;
	default:
		printf("arp op %x: ", fla->op);
		break;
	}
	print_arphdr(fla);
	printf("\n");
}

void print_flow(const struct flow *fl)
{
	print_mac(fl->smac, false);
	printf(" -> ");
	print_mac(fl->dmac, false);

	if (fl->has_vlan) {
		__u16 vlan, prio;

		vlan = fl->vlan.outer_vlan_TCI & VLAN_VID_MASK;
		printf(" vlan %u", vlan);

		prio = (fl->vlan.outer_vlan_TCI & VLAN_PRIO_MASK);
		prio >>= VLAN_PRIO_SHIFT;
		if (prio)
			printf(" prio %u", prio);
	}

	switch(fl->proto) {
	case ETH_P_ARP:
		print_arp(&fl->arp);
		break;
	case ETH_P_IP:
		print_ipv4(&fl->ip4);
		break;
	case ETH_P_IPV6:
		print_ipv6(&fl->ip6);
		break;
	case ETH_P_LLDP:
		printf("    LLDP\n");
		break;
	default:
		printf("    ethernet protocol %x\n", fl->proto);
	}
}

void print_pkt(__u16 protocol, const __u8 *data, int len)
{
	struct flow fl = {};

	if (parse_pkt(&fl, protocol, data, len))
		printf("*** failed to parse packet ***\n");
	else
		print_flow(&fl);
}
