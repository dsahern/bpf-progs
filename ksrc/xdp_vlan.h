#ifndef __XDP_VLAN_H
#define __XDP_VLAN_H

/*
 * helpers for pushing/popping vlan for xdp context
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>

static __always_inline int xdp_vlan_push(struct xdp_md *ctx, __be16 vlan)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u8 smac[ETH_ALEN], dmac[ETH_ALEN];
	struct ethhdr *eth = data;
	struct vlan_hdr *vhdr;
	int delta = sizeof(*vhdr);
	u16 h_proto;
	int rc;

	if (eth + 1 > data_end)
		return -1;

	h_proto = eth->h_proto;
	__builtin_memcpy(smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(dmac, eth->h_dest, ETH_ALEN);

	if (bpf_xdp_adjust_head(ctx, -delta))
		return -1;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	vhdr = data + sizeof(*eth);
	if (vhdr + 1 > data_end)
		return -1;

	vhdr->h_vlan_TCI = vlan;
	vhdr->h_vlan_encapsulated_proto = h_proto;

	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_8021Q);

	return 0;
}

/* pop vlan header if vlan tag is given one.
 * return -1 on error, > 1 if vlan does not match
 */
static __always_inline int xdp_vlan_pop(struct xdp_md *ctx, __be16 vlan)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u8 smac[ETH_ALEN], dmac[ETH_ALEN];
	struct ethhdr *eth = data;
	struct vlan_hdr *vhdr;
	int delta = sizeof(*vhdr);
	u16 h_proto;
	int rc;

	if (eth + 1 > data_end)
		return -1;

	/* expecting a specific vlan tag */
	if (eth->h_proto != htons(ETH_P_8021Q))
		return 1;

	vhdr = data + sizeof(*eth);
	if (vhdr + 1 > data_end)
		return -1;

	if (vhdr->h_vlan_TCI != vlan)
		return 1;

	__builtin_memcpy(smac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(dmac, eth->h_dest, ETH_ALEN);
	h_proto = vhdr->h_vlan_encapsulated_proto;

	/* pop vlan header */
	if (bpf_xdp_adjust_head(ctx, delta))
		return -1;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	if (eth + 1 > data_end)
		return -1;

	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
	eth->h_proto = h_proto;

	return 0;
}
#endif /* __XDP_VLAN_H */
