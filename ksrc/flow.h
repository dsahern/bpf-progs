#ifndef _FLOW_H_
#define _FLOW_H_

#define ENABLE_FLOW_IPV6

struct flow_ports {
	__be16 sport;
	__be16 dport;
};

struct flow_icmp {
	__u8 type;
	__u8 code;
	__be16 id;
};

/* used for dissecting packets */
struct flow {
	union {
		__u32		ipv4;
#ifdef ENABLE_FLOW_IPV6
		struct in6_addr	ipv6;
#endif
	} saddr;

	union {
		__u32		ipv4;
#ifdef ENABLE_FLOW_IPV6
		struct in6_addr ipv6;
#endif
	} daddr;

	__u8 family;    /* network address family */
	__u8 protocol;  /* L4 protocol */
	__u8 fragment;
	__u8 inner_protocol;

	__u32 inner_saddr;
	__u32 inner_daddr;

	union {
		struct flow_ports ports;
		struct flow_icmp icmp;
	};
};

#define PARSE_STOP_AT_NET 0x1
#endif
