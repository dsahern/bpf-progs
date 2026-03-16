// SPDX-License-Identifier: GPL-2.0
/* Example of L2 forwarding via XDP. FDB is a <vlan,dmac> hash table
 * returning device index to redirect packet.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "net_defines.h"
#include "xdp_fdb.h"

/* For TX-traffic redirect requires net_device ifindex to be in this devmap */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(max_entries, 512);
	__type(key, u32);
	__type(value, struct bpf_devmap_val);
} xdp_fwd_ports SEC(".maps");

/* <vlan,dmac> to device index map */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, struct fdb_key);
	__type(value, u32);
} fdb_map SEC(".maps");

SEC("xdp_l2fwd")
int xdp_l2fwd_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_devmap_val *entry;
	struct vlan_hdr *vhdr = NULL;
	struct ethhdr *eth;
	struct fdb_key key;
	u8 smac[ETH_ALEN];
	u16 h_proto = 0;
	void *nh;
	int rc;

	/* data in context points to ethernet header */
	eth = data;

	/* set pointer to header after ethernet header */
	nh = data + sizeof(*eth);
	if (nh > data_end)
		return XDP_DROP; // malformed packet

	__builtin_memset(&key, 0, sizeof(key));
	__builtin_memcpy(key.mac, eth->h_dest, ETH_ALEN);

	if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
		vhdr = nh;
		if ((void *)(vhdr + 1) > data_end)
			return XDP_DROP; // malformed packet

		key.vlan = bpf_ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
	}

	entry = bpf_map_lookup_elem(&fdb_map, &key);
	if (!entry || entry->ifindex == 0)
		return XDP_PASS;

	/* Verify redirect index exists in port map */
	if (!bpf_map_lookup_elem(&xdp_fwd_ports, &entry->ifindex))
		return XDP_PASS;

	if (vhdr) {
		/* remove VLAN header before hand off to VM */
		h_proto = vhdr->h_vlan_encapsulated_proto;
		__builtin_memcpy(smac, eth->h_source, ETH_ALEN);

		if (bpf_xdp_adjust_head(ctx, sizeof(*vhdr)))
			return XDP_PASS;

		/* reset data pointers after adjust */
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return XDP_DROP;

		__builtin_memcpy(eth->h_dest, key.mac, ETH_ALEN);
		__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
		eth->h_proto = h_proto;
	}

	return bpf_redirect_map(&xdp_fwd_ports, entry->ifindex, 0);
}

char _license[] SEC("license") = "GPL";
