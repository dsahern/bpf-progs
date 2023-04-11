// SPDX-License-Identifier: GPL-2.0
/* Example of L3 forwarding via XDP and use of bpf FIB lookup helper.
 *
 * Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */
#define KBUILD_MODNAME "xdp_l3fwd"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>

#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)

struct bpf_map_def SEC("maps") xdp_l3fwd_ports = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 512,
};

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int xdp_l3fwd_flags(struct xdp_md *ctx, u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	u16 h_proto;
	u64 nh_off;
	int rc;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	h_proto = eth->h_proto;
	if (h_proto == htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end)
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.tot_len	= ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.tot_len	= ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else {
		return XDP_PASS;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), flags);
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		if (!bpf_map_lookup_elem(&xdp_l3fwd_ports, &fib_params.ifindex))
			return XDP_PASS;

		if (h_proto == htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		__builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		return bpf_redirect_map(&xdp_l3fwd_ports, fib_params.ifindex, 0);
	}

	return XDP_PASS;
}

SEC("xdp_l3fwd")
int xdp_l3fwd_prog(struct xdp_md *ctx)
{
	return xdp_l3fwd_flags(ctx, 0);
}

SEC("xdp_l3fwd_direct")
int xdp_l3fwd_direct_prog(struct xdp_md *ctx)
{
	return xdp_l3fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT);
}

char _license[] SEC("license") = "GPL";
