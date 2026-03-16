#ifndef _NET_DEFINES_H_
#define _NET_DEFINES_H_

#include <bpf/bpf_endian.h>

// TO-DO: figure out how to pull from header files

#define ETH_P_IP	0x0800
#define ETH_P_8021Q	0x8100
#define ETH_P_IPV6	0x86DD

#define VLAN_VID_MASK 0x0fff

#define AF_INET		2
#define AF_INET6	10
#define ETH_ALEN	6

#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

#define ICMP_ECHOREPLY          0
#define ICMP_ECHO               8
#define ICMP_TIMESTAMP          13
#define ICMP_TIMESTAMPREPLY     14

/* little endian version; big endian swap is not needed */
#define IPV6_FLOWINFO_MASK              bpf_swap32(0x0FFFFFFF)

#define IPPROTO_ICMPV6          58

#define ICMPV6_ECHO_REQUEST             128
#define ICMPV6_ECHO_REPLY               129

static inline u32 ipv6_addr_hash(const struct in6_addr *a)
{
	const unsigned long *ul = (const unsigned long *)a;
	unsigned long x = ul[0] ^ ul[1];

	return (u32)(x ^ (x >> 32));
}

#define TC_ACT_OK               0
#define TC_ACT_RECLASSIFY       1
#define TC_ACT_SHOT             2

#endif
