// SPDX-License-Identifier: GPL-2.0
/* Example of L2 forwarding via XDP. FDB is a <vlan,dmac> hash table
 * returning device index to redirect packet.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#define KBUILD_MODNAME "xdp_l2fwd"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

#include "xdp_fdb.h"

/* For TX-traffic redirect requires net_device ifindex to be in this devmap */
struct bpf_map_def SEC("maps") xdp_fwd_ports = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 512,
};

/* <vlan,dmac> to device index map */
struct bpf_map_def SEC("maps") fdb_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct mac_key),
	.value_size = sizeof(u32),
	.max_entries = 512,
};

SEC("xdp_l2fwd")
int xdp_l2fwd_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vlan_hdr *vhdr;
	struct ethhdr *eth;
	struct mac_key key;
	u8 smac[ETH_ALEN];
	u16 h_proto = 0;
	u32 *entry;
	void *nh;
	int rc;

	/* data in context points to ethernet header */
	eth = data;

	/* set pointer to header after ethernet header */
	nh = data + sizeof(*eth);
	if (nh > data_end)
		return XDP_DROP; // malformed packet

	/* expecting VLAN tag for VM traffic, but not Q-in-Q */
	if (eth->h_proto != htons(ETH_P_8021Q))
		return XDP_PASS;

	vhdr = nh;
	if (vhdr + 1 > data_end)
		return XDP_DROP; // malformed packet

	memset(&key, 0, sizeof(key));
	key.vlan = ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
	if (key.vlan == 0)
		return XDP_PASS;

	memcpy(key.mac, eth->h_dest, ETH_ALEN);

	entry = bpf_map_lookup_elem(&fdb_map, &key);
	if (!entry || *entry == 0)
		return XDP_PASS;

	/* Verify redirect index exists in port map */
	if (!bpf_map_lookup_elem(&xdp_fwd_ports, entry))
		return XDP_PASS;

	/* remove VLAN header before hand off to VM */
	h_proto = vhdr->h_vlan_encapsulated_proto;
	memcpy(smac, eth->h_source, ETH_ALEN);

	if (bpf_xdp_adjust_head(ctx, sizeof(*vhdr)))
		return XDP_PASS;

	/* reset data pointers after adjust */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if (eth + 1 > data_end)
		return XDP_DROP;

	memcpy(eth->h_dest, key.mac, ETH_ALEN);
	memcpy(eth->h_source, smac, ETH_ALEN);
	eth->h_proto = h_proto;

	return bpf_redirect_map(&xdp_fwd_ports, *entry, 0);
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
