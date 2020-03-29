#ifndef _XDP_FDB_H_
#define _XDP_FDB_H_

#include <linux/if_ether.h>

struct xdp_stats {
	__u64 bytes_fwd;
	__u64 pkts_fwd;
	__u64 dropped;
};

struct mac_key
{
	__u8  mac[ETH_ALEN];
	__u16 vlan;
};

#endif
