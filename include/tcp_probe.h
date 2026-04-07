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

#endif
