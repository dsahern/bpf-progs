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
#include "acl_simple.h"

struct bpf_map_def SEC("maps") rx_acl_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct acl_key),
	.value_size = sizeof(struct acl_val),
	.max_entries = 64,
};

SEC("classifier/rx_acl")
int tc_acl_rx_prog(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	u32 idx = skb->ifindex;
	struct flow fl = {};
	bool rc;

	rc = drop_packet(data, data_end, NULL, true, &fl, &rx_acl_map);

	return rc ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("xdp/rx_acl")
int xdp_rx_acl_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct flow fl = {};
	bool rc;

	rc = drop_packet(data, data_end, NULL, true, &fl, &rx_acl_map);

	return rc ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
