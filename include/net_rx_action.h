/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_RX_LATENCY_H_
#define _NET_RX_LATENCY_H_

#define MAX_CPUS	128

#define NET_RX_BUCKET_0    100
#define NET_RX_BUCKET_1    500
#define NET_RX_BUCKET_2   1000
#define NET_RX_BUCKET_3   2500
#define NET_RX_BUCKET_4   5000
#define NET_RX_BUCKET_5  10000
#define NET_RX_BUCKET_6  50000
/* bucket 7 is anything > than bucket 6 */
/* bucket 8 is errors */

#define NET_RX_NUM_BKTS  9

struct net_rx_hist_val {
	__u64 buckets[NET_RX_NUM_BKTS];
};

#endif
