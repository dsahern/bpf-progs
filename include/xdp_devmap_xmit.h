/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _DEVMAP_XMIT_H_
#define _DEVMAP_XMIT_H_

#define DEVMAP_BUCKETS 10
struct devmap_xmit_hist {
        __u64 buckets[DEVMAP_BUCKETS];
};

#endif
