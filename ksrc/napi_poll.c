// SPDX-License-Identifier: GPL-2.0
/* Track histogram of napi poll
 *
 * Copyright (c) 2020 David Ahern <dsahern@gmail.com>
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "napi_poll.h"
#include "bpf_debug.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct napi_poll_hist);
} napi_poll_map SEC(".maps");

SEC("tracepoint/napi/napi_poll")
int bpf_napi_poll(struct napi_poll_args *ctx)
{
	struct napi_poll_hist *hist;
	__u32 idx = 0;

	if (bpf_get_smp_processor_id() != 5)
		return 0;

	//bpf_debug("work %d budget %d\n", ctx->work, ctx->budget);
	hist = bpf_map_lookup_elem(&napi_poll_map, &idx);
	if (hist) {
		u64 *c;

		/* update hist entry */
		if (ctx->work == 0)
			c = &hist->buckets[0];
		else if (ctx->work == 1)
			c = &hist->buckets[1];
		else if (ctx->work == 2)
			c = &hist->buckets[2];
		else if (ctx->work < 5)
			c = &hist->buckets[3];
		else if (ctx->work < 9)
			c = &hist->buckets[4];
		else if (ctx->work < 17)
			c = &hist->buckets[5];
		else if (ctx->work < 33)
			c = &hist->buckets[6];
		else if (ctx->work < 64)
			c = &hist->buckets[7];
		else
			c = &hist->buckets[8];

		__sync_fetch_and_add(c, 1);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
