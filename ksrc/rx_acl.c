// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 *
 * Rx ACL
 */
#define KBUILD_MODNAME "rx_acl"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

#include "xdp_acl.h"
#include "eth_helpers.h"

#include "flow.h"

struct bpf_map_def SEC("maps") rx_acl_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct acl_key),
	.value_size = sizeof(struct acl_val),
	.max_entries = 64,
};

static __always_inline bool my_ipv6_addr_cmp(const struct in6_addr *a1,
					     const struct in6_addr *a2)
{
	return a1->s6_addr32[0] == a2->s6_addr32[0] &&
	       a1->s6_addr32[1] == a2->s6_addr32[1] &&
	       a1->s6_addr32[2] == a2->s6_addr32[2] &&
	       a1->s6_addr32[3] == a2->s6_addr32[3];
}

static __always_inline bool ipv6_any(const struct in6_addr *a1)
{
	struct in6_addr a2 = {};

	return my_ipv6_addr_cmp(a1, &a2);
}

/* returns true if packet should be dropped; false to continue */
static __always_inline bool drop_packet(void *data, void *data_end,
					u32 dev_idx, struct flow *fl,
					struct bpf_map_def *acl_map)
{
	struct ethhdr *eth = data;
	struct acl_key key = {};
	struct acl_val *val;
	void *nh = eth + 1;
	u16 h_proto;
	int rc;

	if (nh > data_end)
		return true;

	h_proto = eth->h_proto;
	rc = parse_pkt(fl, h_proto, nh, data_end, 0);
	if (rc)
		return rc > 0 ? false : true;

	key.protocol = fl->protocol;
	if (key.protocol == IPPROTO_TCP || key.protocol == IPPROTO_UDP)
		key.port = fl->ports.dport;

	val = bpf_map_lookup_elem(acl_map, &key);
	/* if no entry, pass */
	if (!val) {
		/* check for just protocol; maybe a sport ACL */
		key.port = 0;
		val = bpf_map_lookup_elem(acl_map, &key);
	}
	if (!val)
		return false;

	/* action on hit */
	if (val->family) {
		if (fl->family != val->family)
			return false;
	} else if (val->flags & (ACL_FLAG_SADDR_CHECK | ACL_FLAG_DADDR_CHECK)) {
		if (fl->family != val->family)
			return false;
	}
	if (val->flags & ACL_FLAG_SADDR_CHECK) {
		switch(fl->family) {
		case AF_INET:
			if (!val->saddr.ipv4)
				return true;
			if (fl->saddr.ipv4 != val->saddr.ipv4)
				return false;
			break;
		case AF_INET6:
			if (ipv6_any(&val->saddr.ipv6))
				return true;
			if (!my_ipv6_addr_cmp(&fl->saddr.ipv6, &val->saddr.ipv6))
				return false;
			break;
		default:
			return false;
		}
	}
	if (val->flags & ACL_FLAG_DADDR_CHECK) {
		switch(fl->family) {
		case AF_INET:
			if (!val->daddr.ipv4)
				return true;
			if (fl->daddr.ipv4 != val->daddr.ipv4)
				return false;
			break;
		case AF_INET6:
			if (ipv6_any(&val->daddr.ipv6))
				return true;
			if (!my_ipv6_addr_cmp(&fl->daddr.ipv6, &val->daddr.ipv6))
				return false;
			break;
		default:
			return false;
		}
	}

	if (val->port && val->port == fl->ports.sport)
		return true;

	return true;
}

SEC("classifier/rx_acl")
int tc_acl_rx_prog(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	u32 idx = skb->ifindex;
	struct flow fl = {};
	bool rc;

	rc = drop_packet(data, data_end, idx, &fl, &rx_acl_map);

	return rc ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("xdp/rx_acl")
int xdp_rx_acl_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 idx = ctx->ingress_ifindex;
	struct flow fl = {};
	bool rc;

	rc = drop_packet(data, data_end, idx, &fl, &rx_acl_map);

	return rc ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
