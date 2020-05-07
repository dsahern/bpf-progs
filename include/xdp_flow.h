#ifndef _XDP_FLOW_H_
#define _XDP_FLOW_H_

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
		struct in6_addr	ipv6;
	} saddr;

	union {
		__u32		ipv4;
		struct in6_addr ipv6;
	} daddr;

	__u8 family;    /* address family */
	__u8 protocol;  /* L4 protocol */
	__u8 fragment;
	__u8 tbd;

	union {
		struct flow_ports ports;
		struct flow_icmp icmp;
	};
};

#endif
