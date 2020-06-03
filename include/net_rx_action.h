/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_RX_LATENCY_H_
#define _NET_RX_LATENCY_H_

#define MAX_CPUS	128

#define NET_RX_BUCKET_0     5
#define NET_RX_BUCKET_1    10
#define NET_RX_BUCKET_2    25
#define NET_RX_BUCKET_3    50
#define NET_RX_BUCKET_4   100
#define NET_RX_BUCKET_5   500
#define NET_RX_BUCKET_6  1000
#define NET_RX_BUCKET_7  2000
#define NET_RX_BUCKET_8  5000

/* bucket 9 is anything > than bucket 8 */
/* bucket 10 is errors */

#define NET_RX_NUM_BKTS  11
#define NET_RX_ERR_BKT (NET_RX_NUM_BKTS-1)

struct net_rx_hist_val {
	__u64 buckets[NET_RX_NUM_BKTS];
};

#endif
