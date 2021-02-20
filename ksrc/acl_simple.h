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
#include "ipv6_helpers.h"
#include "flow.h"

static __always_inline bool acl_simple(struct ethhdr *eth, struct flow *fl,
				      bool use_src, struct bpf_map_def *acl_map)
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
	} else if (val->flags & ACL_FLAG_ADDR_CHECK) {
		if (fl->family != val->family)
			return false;
	}
	if (val->flags & ACL_FLAG_ADDR_CHECK) {
		struct in6_addr *v6addr;
		__be32 v4addr;

		switch(fl->family) {
		case AF_INET:
			if (!val->addr.ipv4)
				return true;

			v4addr = use_src ? fl->saddr.ipv4 : fl->daddr.ipv4;
			if (v4addr != val->addr.ipv4)
				return false;
			break;
		case AF_INET6:
			if (ipv6_is_any(&val->addr.ipv6))
				return true;

			v6addr = use_src ? &fl->saddr.ipv6 : &fl->daddr.ipv6;
			if (!do_ipv6_addr_cmp(v6addr, &val->addr.ipv6))
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
	bool rc = false;
	int ret;

	if (eth + 1 > data_end)
		return true;

	/* direction: Tx = to VM, Rx = from VM */
	if (vi && !mac_cmp(vi->mac, rx ? eth->h_source : eth->h_dest))
		return true;

	ret = parse_pkt(fl, data, data_end, 0);
	if (ret)
		return ret > 0 ? false : true;

	/* Rx = from VM: check dest address against ACL
	 * Tx = to VM: check source address against ACL
	 */
	if (acl_map)
		rc = acl_simple(eth, fl, !rx, acl_map);

	return rc;
}
