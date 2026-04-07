/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_NAPI_POLL_H_
#define _NET_NAPI_POLL_H_

#define NAPI_BUCKETS  9
struct napi_poll_hist {
        __u64 buckets[NAPI_BUCKETS];
};

#endif
