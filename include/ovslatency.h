/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _OVSLATENCY_H_
#define _OVSLATENCY_H_

#define OVS_BUCKET_0    10
#define OVS_BUCKET_1    25
#define OVS_BUCKET_2    50
#define OVS_BUCKET_3   100
#define OVS_BUCKET_4   250
#define OVS_BUCKET_5   500
/* bucket 6 is > 5 */
/* bucket 7 is total number of packets */

struct ovslat_hist_val {
	__u64 buckets[8];
};

#endif
