// SPDX-License-Identifier: GPL-2.0
/* Handle traffic from a VM. Expects host NICs to be into a bond
 * configured with L3+L4 hashing to spread traffic across ports.
 *
 * Copyright (c) 2019-20 David Ahern <dsahern@gmail.com>
 */
#define KBUILD_MODNAME "xdp_vmegress"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>

#include "xdp_vlan.h"
#include "acl_simple.h"

/* TO-DO: pull this from a map */
#define EGRESS_ETH0   2
#define EGRESS_ETH1   3

/* For TX-traffic redirect requires net_device ifindex to be in this devmap */
struct bpf_map_def SEC("maps") __egress_ports = {
	.type = BPF_MAP_TYPE_DEVMAP_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct bpf_devmap_val),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") __acl_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct acl_key),
        .value_size = sizeof(struct acl_val),
        .max_entries = 64,
};

struct bpf_map_def SEC("maps") __vm_info_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct vm_info),
	.max_entries = 1,
};

static __always_inline u32 bond_hash(struct flow *fl)
{
	u32 hash, idx;

	/* flow_icmp and flow_ports are a union in flow
	 * and both are u32 in size
	 */
	__builtin_memcpy(&hash, &fl->ports, sizeof(hash));

	if (fl->family == AF_INET) {
		hash ^= fl->daddr.ipv4 ^ fl->saddr.ipv4;
	} else if (fl->family == AF_INET6) {
		hash ^= ipv6_addr_hash(&fl->daddr.ipv6);
		hash ^= ipv6_addr_hash(&fl->saddr.ipv6);
	}

	hash ^= (hash >> 16);
	hash ^= (hash >> 8);
	hash = (hash >> 1);

	idx = hash & 1 ? EGRESS_ETH1 : EGRESS_ETH0;

	return idx;
}

SEC("xdp/egress")
int xdp_egress_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 idx = ctx->ingress_ifindex;
	struct ethhdr *eth = data;
	struct flow fl = {};
	struct vm_info *vi;
	u16 h_proto;
	int rc;

	vi = bpf_map_lookup_elem(&__vm_info_map, &idx);
	if (!vi)
		return XDP_PASS;

        if (drop_packet(data, data_end, vi, true, &fl, &__acl_map))
		return XDP_DROP;

	/* don't redirect broadcast frames */
	if (eth->h_dest[0] == 0xff)
		return XDP_PASS;

	if (vi->vlan_TCI && xdp_vlan_push(ctx, vi->vlan_TCI) < 0)
		return XDP_PASS;

	idx = bond_hash(&fl);

	return bpf_redirect_map(&__egress_ports, idx, 0);
}

char _license[] SEC("license") = "GPL";
