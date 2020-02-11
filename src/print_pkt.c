// SPDX-License-Identifier: GPL-2.0
/* Functions to pretty print packet headers
 *
 * David Ahern <dsahern@gmail.com>
 */
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

#include "print_pkt.h"
#include "str_utils.h"

static void dump_data(const __u8 *data, __u32 len)
{
	char buf[256], bytes[10];
	int i, j;

	if (len & (len - 1))
		len--;

	buf[0] = 0;
	for (i = 0, j = 0; i < len; i+=2, ++j) {
		sprintf(bytes ,"%2.2x%2.2x ", data[i], data[i+1]);
		strcat(buf, bytes);
		if (j == 7) {
			j = -1;
			printf("%s  ", buf);
			buf[0] = 0;
		}
	}
	if (buf[0])
		printf("%s", buf);

	printf("\n");
}

static void print_tcp(const struct tcphdr *tcph, const char *src,
		      const char *dst)
{
	printf("    TCP: src=%s/%d -> dst=%s/%d",
		src, ntohs(tcph->source),
		dst, ntohs(tcph->dest));

	if (tcph->syn)
		printf(" SYN");
	if (tcph->ack)
		printf(" ACK");
	if (tcph->psh)
		printf(" PSH");
	if (tcph->fin)
		printf(" FIN");
	if (tcph->rst)
		printf(" RST");

	printf("\n");
}

static void print_udp(const struct udphdr *udph, const char *src,
		      const char *dst)
{
	printf("    UDP: src=%s/%d -> dst=%s/%d\n",
		src, ntohs(udph->source),
		dst, ntohs(udph->dest));
}

static void print_ipv6(const __u8 *data, __u32 len)
{
	const struct ipv6hdr *ip6h = (const struct ipv6hdr *)data;
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	const struct udphdr *udph;
	const struct tcphdr *tcph;
	unsigned int hlen;

	if (len < sizeof(struct ipv6hdr)) {
		printf("    packet snippet too small for ipv6 header\n");
		dump_data(data, len);
		return;
	}

	inet_ntop(AF_INET6, &ip6h->saddr, src, sizeof(src));
	inet_ntop(AF_INET6, &ip6h->daddr, dst, sizeof(dst));

	hlen = sizeof(*ip6h);
	switch(ip6h->nexthdr) {
	case IPPROTO_TCP:
		if (len < hlen + sizeof(*tcph)) {
			printf("    ipv6 packet snippet too small for tcp ports\n");
			return;
		}
		tcph = (struct tcphdr *)(data + hlen);
		print_tcp(tcph, src, dst);
		break;
	case IPPROTO_UDP:
		if (len < hlen + sizeof(*udph)) {
			printf("    ipv6 packet snippet too small for udp ports\n");
			return;
		}
		udph = (struct udphdr *)(data + hlen);
		print_udp(udph, src, dst);
		break;
	case IPPROTO_VRRP:
		printf("    VRRP: src=%s -> dst=%s\n",
			src, dst);
		break;
	default:
		printf("    protocol %u: src=%s -> dst=%s\n",
			ip6h->nexthdr, src, dst);
		//dump_data(data, len);
	}

	return;
}

static void print_arphdr(const struct arphdr *arph, __u32 len)
{
	struct arpdata *arp_data;
	char addr[INET_ADDRSTRLEN];

	if (arph->ar_pro != htons(ETH_P_IP) || arph->ar_pln != 4) {
		printf("    protocol address not IPv4");
		return;
	}

	if (ntohs(arph->ar_hrd) != ARPHRD_ETHER || arph->ar_hln != ETH_ALEN) {
		printf("    hardware address not ethernet");
		return;
	}

	if (len < sizeof(*arp_data)) {
		printf("    packet sample snippet too small for arp data\n");
		return;
	}
	arp_data = (struct arpdata *)(arph + 1);
	inet_ntop(AF_INET, &arp_data->ar_sip, addr, sizeof(addr));
	printf("sender: %s ", addr);
	print_mac(arp_data->ar_sha, false);

	inet_ntop(AF_INET, &arp_data->ar_tip, addr, sizeof(addr));
	printf(" target: %s ", addr);
	print_mac(arp_data->ar_tha, false);
}

static void print_arp(const __u8 *data, __u32 len)
{
	const struct arphdr *arph = (const struct arphdr *)data;

	if (len < sizeof(*arph)) {
		printf("    packet snippet too small for arp header\n");
		return;
	}
	len -= sizeof(*arph);

	printf("    ");
	switch(ntohs(arph->ar_op)) {
	case ARPOP_REQUEST:
		printf("arp request: ");
		print_arphdr(arph, len);
		break;
	case ARPOP_REPLY:
		printf("arp reply: ");
		print_arphdr(arph, len);
		break;
	case ARPOP_RREQUEST:
		printf("rarp request: ");
		print_arphdr(arph, len);
		break;
	case ARPOP_RREPLY:
		printf("rarp reply: ");
		print_arphdr(arph, len);
		break;
	default:
		printf("arp op %x: ", ntohs(arph->ar_op));
		print_arphdr(arph, len);
		break;
	}
	printf("\n");
}

static void print_ipv4(const __u8 *data, __u32 len)
{
	const struct iphdr *iph = (const struct iphdr *)data;
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
	const struct udphdr *udph;
	const struct tcphdr *tcph;
	unsigned int hlen;

	if (len < sizeof(*iph)) {
		printf("    packet snippet too small for ipv4 header\n");
		dump_data(data, len);
		return;
	}

	inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
	inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));

	hlen = iph->ihl << 2;
	switch(iph->protocol) {
	case IPPROTO_TCP:
		if (len < hlen + sizeof(*tcph)) {
			printf("    ipv4 packet snippet too small for tcp ports\n");
			return;
		}
		tcph = (struct tcphdr *)(data + hlen);
		print_tcp(tcph, src, dst);
		break;
	case IPPROTO_UDP:
		if (len < hlen + sizeof(*udph)) {
			printf("    ipv4 packet snippet too small for udp ports\n");
			return;
		}
		udph = (struct udphdr *)(data + hlen);
		print_udp(udph, src, dst);
		break;
	case IPPROTO_VRRP:
		printf("    VRRP: src=%s -> dst=%s\n",
			src, dst);
		break;
	default:
		printf("    protocol %d packet: src=%s -> dst=%s\n",
			iph->protocol, src, dst);
		//dump_data(data, len);
	}

	return;
}

void print_pkt(__u16 protocol, __u8 *data, int len)
{
	const struct ethhdr *eth = (const struct ethhdr *)data;
	unsigned int hlen = sizeof(*eth);

	if (ntohs(eth->h_proto) == ETH_P_8021Q)
		hlen += sizeof(struct vlan_hdr);

	data += hlen;
	len -= hlen;

	switch(ntohs(protocol)) {
	case ETH_P_ARP:
		print_arp(data, len);
		break;
	case ETH_P_IP:
		print_ipv4(data, len);
		break;
	case ETH_P_IPV6:
		print_ipv6(data, len);
		break;
	case ETH_P_LLDP:
		printf("    LLDP\n");
		break;
	default:
		data -= hlen;
		len += hlen;
		printf("    unknown packet, ethernet protocol %x\n",
			ntohs(protocol));
		dump_data(data, len);
	}
}
