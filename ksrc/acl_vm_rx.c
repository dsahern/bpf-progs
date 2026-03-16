// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 *
 * Rx ACL for a VM - packets from VM
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct acl_key);
	__type(value, struct acl_val);
} acl_map SEC(".maps");

#include "acl_simple.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct vm_info);
} vm_info_map SEC(".maps");

SEC("classifier/acl_vm_rx")
int tc_acl_vm_rx_prog(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	u32 idx = skb->ifindex;
	struct flow fl = {};
	struct vm_info *vi;
	bool rc;

	vi = bpf_map_lookup_elem(&vm_info_map, &idx);
	if (!vi)
		return TC_ACT_OK;

	rc = drop_packet(data, data_end, vi, true, &fl);

	return rc ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("xdp/acl_vm_rx")
int xdp_acl_vm_rx_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 idx = ctx->ingress_ifindex;
	struct flow fl = {};
	struct vm_info *vi;
	bool rc;

	vi = bpf_map_lookup_elem(&vm_info_map, &idx);
	if (!vi)
		return XDP_PASS;

	rc = drop_packet(data, data_end, vi, true, &fl);

	return rc ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
