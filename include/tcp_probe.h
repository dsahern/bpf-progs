/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TCP_PROBE_H_
#define _TCP_PROBE_H_

struct data {
	__u64 time;
	union {
		struct sockaddr         s_addr;   /* for sa_family check */
		struct sockaddr_in      s_in;     /* for ipv4 */
		struct sockaddr_in6     s_in6;    /* memory allocated */
	};
	union {
		struct sockaddr         d_addr;   /* for sa_family check */
		struct sockaddr_in      d_in;     /* for ipv4 */
		struct sockaddr_in6     d_in6;    /* memory allocated */
	};

	__u32 mark;
	__u16 cpu;
	__u16 data_len;    /* tcp payload length */
	__u32 snd_nxt;     /* next sequence we send */
	__u32 snd_una;     /* first byte we want an ack for */
	__u32 snd_cwnd;    /* sending congestion window */
	__u32 ssthresh;
	__u32 snd_wnd;     /* window we expect to receive */
	__u32 rcv_wnd;     /* current receiver window */
	__u32 srtt;        /* smoothed round trip time */
};

/* order of arguments from
 * /sys/kernel/debug/tracing/events/tcp/tcp_probe/format
 * but skipping all of the common fields:
 *
        field:__u8 saddr[sizeof(struct sockaddr_in6)];  offset:8;       size:28;        signed:0;
        field:__u8 daddr[sizeof(struct sockaddr_in6)];  offset:36;      size:28;        signed:0;
        field:__u16 sport;      offset:64;      size:2; signed:0;
        field:__u16 dport;      offset:66;      size:2; signed:0;
        field:__u32 mark;       offset:68;      size:4; signed:0;
        field:__u16 data_len;   offset:72;      size:2; signed:0;
        field:__u32 snd_nxt;    offset:76;      size:4; signed:0;
        field:__u32 snd_una;    offset:80;      size:4; signed:0;
        field:__u32 snd_cwnd;   offset:84;      size:4; signed:0;
        field:__u32 ssthresh;   offset:88;      size:4; signed:0;
        field:__u32 snd_wnd;    offset:92;      size:4; signed:0;
        field:__u32 srtt;       offset:96;      size:4; signed:0;
        field:__u32 rcv_wnd;    offset:100;     size:4; signed:0;
        field:__u64 sock_cookie;        offset:104;     size:8; signed:0;

5.13:
        field:__u8 saddr[sizeof(struct sockaddr_in6)];  offset:8;       size:28;        signed:0;
        field:__u8 daddr[sizeof(struct sockaddr_in6)];  offset:36;      size:28;        signed:0;
        field:__u16 sport;      offset:64;      size:2; signed:0;
        field:__u16 dport;      offset:66;      size:2; signed:0;
        field:__u16 family;     offset:68;      size:2; signed:0;
        field:__u32 mark;       offset:72;      size:4; signed:0;
        field:__u16 data_len;   offset:76;      size:2; signed:0;
        field:__u32 snd_nxt;    offset:80;      size:4; signed:0;
        field:__u32 snd_una;    offset:84;      size:4; signed:0;
        field:__u32 snd_cwnd;   offset:88;      size:4; signed:0;
        field:__u32 ssthresh;   offset:92;      size:4; signed:0;
        field:__u32 snd_wnd;    offset:96;      size:4; signed:0;
        field:__u32 srtt;       offset:100;     size:4; signed:0;
        field:__u32 rcv_wnd;    offset:104;     size:4; signed:0;
        field:__u64 sock_cookie;        offset:112;     size:8; signed:0;
 */
struct tcp_probe_args {
	unsigned long long unused;

	union {
		struct sockaddr         s_addr;   /* for sa_family check */
		struct sockaddr_in      s_in;     /* for ipv4 */
		struct sockaddr_in6     s_in6;    /* memory allocated */
	};
	union {
		struct sockaddr         d_addr;   /* for sa_family check */
		struct sockaddr_in      d_in;     /* for ipv4 */
		struct sockaddr_in6     d_in6;    /* memory allocated */
	};

	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 hole1;
	__u32 mark;
	__u16 data_len;
	__u16 hole2;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 snd_cwnd;
	__u32 ssthresh;
	__u32 snd_wnd;
	__u32 srtt;
	__u32 rcv_wnd;
	__u32 hole3;
	__u64 sock_cookie;
} __attribute__ ((packed));

#endif
