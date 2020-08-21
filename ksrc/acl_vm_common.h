// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 *
 * Implement simple address / protocol / port ACL for a
 * VM, but implemented in a host.
 */
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
#include "vm_info.h"
#include "eth_helpers.h"

#include "flow.h"

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
	return a1->s6_addr32[0] == 0 &&
	       a1->s6_addr32[1] == 0 &&
	       a1->s6_addr32[2] == 0 &&
	       a1->s6_addr32[3] == 0;
}

static __always_inline bool check_acl(struct ethhdr *eth, struct flow *fl,
				      struct bpf_map_def *acl_map)
{
	struct acl_key key = {};
	struct acl_val *val;

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

	return key.port ? true : false;
}

/* returns true if packet should be dropped; false to continue */
static __always_inline bool drop_packet(void *data, void *data_end,
					struct vm_info *vi, bool rx,
					struct flow *fl,
					struct bpf_map_def *acl_map)
{
	struct ethhdr *eth = data;
	void *nh = eth + 1;
	bool rc = false;
	u16 h_proto;
	int ret;


	if (nh > data_end)
		return true;

	/* direction: Tx = to VM, Rx = from VM */
	if (!mac_cmp(vi->mac, rx ? eth->h_source : eth->h_dest))
		return true;

	h_proto = eth->h_proto;
#ifdef SUPPORT_QINQ
	if (h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = nh;
		if (vhdr + 1 > data_end)
			return true;

		nh += sizeof(*vhdr);
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
#endif
	if (h_proto == htons(ETH_P_8021Q)) {
		struct vlan_hdr *vhdr;

		vhdr = nh;
		if (vhdr + 1 > data_end)
			return true;

		nh += sizeof(*vhdr);
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	ret = parse_pkt(fl, h_proto, nh, data_end, 0);
	if (ret)
		return ret > 0 ? false : true;

	if (acl_map)
		rc = check_acl(eth, fl, acl_map);

	return rc;
}
