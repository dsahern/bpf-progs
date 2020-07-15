#ifndef __XDP_ACL_H_
#define __XDP_ACL_H_

struct acl_key
{
	__be16	port;
	__u8	protocol;  /* ip protocol (TCP, UDP, ...) */
};

#define ACL_FLAG_SADDR_CHECK   (1<<0)
#define ACL_FLAG_DADDR_CHECK   (1<<1)

struct acl_val
{
	union {
		__u32		ipv4;
		struct in6_addr	ipv6;
	} saddr;

	union {
		__u32		ipv4;
		struct in6_addr	ipv6;
	} daddr;

	__u8	family;
	__u8	flags;
	__be16	port;
};

#endif
