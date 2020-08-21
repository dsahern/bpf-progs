// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 *
 * Rx ACL for a VM - packets from VM
 */
#define KBUILD_MODNAME "acl_vm_rx"
#include <uapi/linux/bpf.h>

#include "acl_vm_common.h"

struct bpf_map_def SEC("maps") __rx_acl_map = {
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

SEC("classifier/acl_vm_rx")
int tc_acl_vm_rx_prog(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	u32 idx = skb->ifindex;
	struct flow fl = {};
	struct vm_info *vi;
	bool rc;

	vi = bpf_map_lookup_elem(&__vm_info_map, &idx);
	if (!vi)
		return TC_ACT_OK;

	rc = drop_packet(data, data_end, vi, true, &fl, &__rx_acl_map);

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

	vi = bpf_map_lookup_elem(&__vm_info_map, &idx);
	if (!vi)
		return XDP_PASS;

	rc = drop_packet(data, data_end, vi, true, &fl, &__rx_acl_map);

	return rc ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
