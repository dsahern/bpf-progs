// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 *
 * Rx ACL
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "xdp_acl.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct acl_key);
	__type(value, struct acl_val);
} acl_map SEC(".maps");

#include "acl_simple.h"

SEC("classifier/rx_acl")
int tc_acl_rx_prog(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	u32 idx = skb->ifindex;
	struct flow fl = {};
	bool rc;

	rc = drop_packet(data, data_end, NULL, true, &fl);

	return rc ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("xdp/rx_acl")
int xdp_rx_acl_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct flow fl = {};
	bool rc;

	rc = drop_packet(data, data_end, NULL, true, &fl);

	return rc ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
