#ifndef __VM_INFO_H_
#define __VM_INFO_H_

struct vm_info
{
	__u32		vmid;
	__u8		mac[ETH_ALEN];
	__be16		vlan_TCI;  /* vlan tag to add on egress redirect */
	__u32		v4addr;
	struct in6_addr	v6addr;
};

#endif
