// SPDX-License-Identifier: GPL-2.0
/* Track histogram of work done on devmap flush
 *
 * Copyright (c) 2020 David Ahern <dsahern@gmail.com>
 */

#define KBUILD_MODNAME "xdp_devmap_xmit"
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xdp_devmap_xmit.h"

#include "bpf_debug.h"

struct bpf_map_def SEC("maps") devmap_xmit_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct devmap_xmit_hist),
	.max_entries = 1,
};

SEC("tracepoint/xdp/xdp_devmap_xmit")
int bpf_devmap_xmit(struct devmap_xmit_args *ctx)
{
	struct devmap_xmit_hist *hist;
	__u32 idx = 0;

	hist = bpf_map_lookup_elem(&devmap_xmit_map, &idx);
	if (hist) {
		u64 *c;

		/* update hist entry */
		if (ctx->sent == 0)
			c = &hist->buckets[0];
		else if (ctx->sent == 1)
			c = &hist->buckets[1];
		else if (ctx->sent == 2)
			c = &hist->buckets[2];
		else if (ctx->sent < 5)
			c = &hist->buckets[3];
		else if (ctx->sent < 9)
			c = &hist->buckets[4];
		else if (ctx->sent < 16)
			c = &hist->buckets[5];
		else if (ctx->sent == 16)
			c = &hist->buckets[6];
		else if (ctx->sent < 33)
			c = &hist->buckets[7];
		else if (ctx->sent < 64)
			c = &hist->buckets[8];
		else
			c = &hist->buckets[9];

		__sync_fetch_and_add(c, 1);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
