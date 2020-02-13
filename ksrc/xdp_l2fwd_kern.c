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

struct bpf_map_def SEC("maps") fdb_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct mac_key),
	.value_size = sizeof(u32),
	.max_entries = 512,
};

struct bpf_map_def SEC("maps") stats_map = {
	.type		= BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size	= sizeof(u32),
	.value_size	= sizeof(struct xdp_stats),
	.max_entries	= 4
};

static __always_inline void xdp_stats_drop(struct xdp_md *ctx)
{
#ifdef HAVE_INGRESS_IFINDEX
	int idx = ctx->ingress_ifindex;
	struct xdp_stats *stats;

	stats = bpf_map_lookup_elem(&stats_map, &idx);
	if (stats) {
		stats->dropped++;
	} else {
		struct xdp_stats stats2 = { .dropped = 1 };
		bpf_map_update_elem(&stats_map, &idx, &stats2, BPF_ANY);
	}
#endif
}

#ifdef GET_FWD_STATS
static __always_inline void xdp_stats_fwd(int idx, int len)
{
	struct xdp_stats *stats;

	if (len < 0)
		len = 0;

	stats = bpf_map_lookup_elem(&stats_map, &idx);
	if (stats) {
		stats->pkts_fwd++;
		stats->bytes_fwd += len;
	} else {
		struct xdp_stats stats2 = { .pkts_fwd = 1, .bytes_fwd = len };

		bpf_map_update_elem(&stats_map, &idx, &stats2, BPF_ANY);
	}
}
#endif

SEC("xdp_l2fwd")
int xdp_l2fwd_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vlan_hdr *vhdr = NULL;
	struct ethhdr *eth = data;
	struct mac_key key;
	u32 *entry;
	u16 h_proto = 0;
	void *nh;
	int rc;

	nh = data + sizeof(*eth);
	if (nh > data_end) {
		xdp_stats_drop(ctx);
		return XDP_DROP; // malformed packet
	}

	memset(&key, 0, sizeof(key));
	memcpy(key.mac, eth->h_dest, ETH_ALEN);

	if (eth->h_proto != htons(ETH_P_8021Q))
		return XDP_PASS;

	vhdr = nh;
	if (vhdr + 1 > data_end) {
		xdp_stats_drop(ctx);
		return XDP_DROP;
	}

	key.vlan = ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
	h_proto = vhdr->h_vlan_encapsulated_proto;

	if (key.vlan == 0)
		return XDP_PASS;

	entry = bpf_map_lookup_elem(&fdb_map, &key);
	if (!entry || *entry == 0)
		return XDP_PASS;

	if (vhdr) {
		u8 smac[ETH_ALEN];

		memcpy(smac, eth->h_source, ETH_ALEN);

		if (bpf_xdp_adjust_head(ctx, sizeof(*vhdr)))
			return XDP_PASS;

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		if (eth + 1 > data_end) {
			xdp_stats_drop(ctx);
			return XDP_DROP;
		}
		memcpy(eth->h_dest, key.mac, ETH_ALEN);
		memcpy(eth->h_source, smac, ETH_ALEN);
		eth->h_proto = h_proto;
	}

	/* requires newer kernel to verify redirect index */
	//if (!bpf_map_lookup_elem(&xdp_fwd_ports, &ifindex))
	//	return XDP_PASS;

#ifdef GET_FWD_STATS
	{
		int pkt_sz = data_end - data;

		xdp_stats_fwd(*entry, pkt_sz);
	}
#endif

	return bpf_redirect_map(&xdp_fwd_ports, *entry, 0);
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
