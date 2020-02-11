/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PRINT_PKT_H
#define __PRINT_PKT_H

#include <linux/if_ether.h>

// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define IPPROTO_VRRP 112

#ifndef ETH_P_LLDP
#define ETH_P_LLDP      0x88CC          /* Link Layer Discovery Protocol */
#endif

struct vlan_hdr {
	__be16  h_vlan_TCI;
	__be16  h_vlan_encapsulated_proto;
};

struct arpdata {
	__u8 ar_sha[ETH_ALEN];
	__u8 ar_sip[4];
	__u8 ar_tha[ETH_ALEN];
	__u8 ar_tip[4];
};

void print_pkt(__u16 protocol, __u8 *data, int len);

#endif
