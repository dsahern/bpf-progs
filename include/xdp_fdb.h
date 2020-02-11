#ifndef _XDP_FDB_H_
#define _XDP_FDB_H_

#include <linux/if_ether.h>

struct mac_key
{
	u8  mac[ETH_ALEN];
	u16 vlan;
};

#endif
