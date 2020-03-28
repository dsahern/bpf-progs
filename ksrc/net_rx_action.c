// SPDX-License-Identifier: GPL-2.0
/* Track time to run net_rx_action
 *
 * Copyright (c) 2020 David Ahern <dsahern@gmail.com>
 */

#define KBUILD_MODNAME "net_rx_action"
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "net_rx_action.h"

struct bpf_map_def SEC("maps") net_rx_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct net_rx_hist_val),
	.max_entries = 1,
};

struct net_rx_enter {
	u64 t_enter;
	int cpu;
};

struct bpf_map_def SEC("maps") net_rx_enter_map = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(u32),
	.value_size     = sizeof(struct net_rx_enter),
	.max_entries    = 1
};

SEC("kprobe/net_rx_action")
int bpf_net_rx_kprobe(struct pt_regs *ctx)
{
	struct net_rx_enter *e;
	bool inc_error = false;
	u32 idx = 0;

	e = bpf_map_lookup_elem(&net_rx_enter_map, &idx);
	if (e) {
		if (e->t_enter || e->cpu != -1)
			inc_error = true;

		e->t_enter = bpf_ktime_get_ns();
		e->cpu = bpf_get_smp_processor_id();
	} else {
		inc_error = true;
	}

	if (inc_error) {
		struct net_rx_hist_val *hist;
		u32 idx = 0;

		hist = bpf_map_lookup_elem(&net_rx_map, &idx);
		if (hist)
			__sync_fetch_and_add(&hist->buckets[NET_RX_ERR_BKT], 1);
	}

	return 0;
}

SEC("kprobe/net_rx_action_ret")
int bpf_net_rx_kprobe_ret(struct pt_regs *ctx)
{
	struct net_rx_hist_val *hist;
	struct net_rx_enter *e;
	u32 idx = 0;

	e = bpf_map_lookup_elem(&net_rx_enter_map, &idx);
	if (!e)
		return 0;

	hist = bpf_map_lookup_elem(&net_rx_map, &idx);
	if (!hist)
		goto out;

	if (e->cpu != bpf_get_smp_processor_id() || !e->t_enter) {
		__sync_fetch_and_add(&hist->buckets[NET_RX_ERR_BKT], 1);
		goto out;
	}

	if (e->t_enter) {
		u64 t = bpf_ktime_get_ns();
		u64 dt = (t - e->t_enter) / 1000;  /* nsec to usec */
		u64 *c;

		/* update hist entry */
		if (dt <= NET_RX_BUCKET_0)
			c = &hist->buckets[0];
		else if (dt <= NET_RX_BUCKET_1)
			c = &hist->buckets[1];
		else if (dt <= NET_RX_BUCKET_2)
			c = &hist->buckets[2];
		else if (dt <= NET_RX_BUCKET_3)
			c = &hist->buckets[3];
		else if (dt <= NET_RX_BUCKET_4)
			c = &hist->buckets[4];
		else if (dt <= NET_RX_BUCKET_5)
			c = &hist->buckets[5];
		else if (dt <= NET_RX_BUCKET_6)
			c = &hist->buckets[6];
		else if (dt <= NET_RX_BUCKET_7)
			c = &hist->buckets[7];
		else if (dt <= NET_RX_BUCKET_8)
			c = &hist->buckets[8];
		else
			c = &hist->buckets[9];

		__sync_fetch_and_add(c, 1);
	}
out:
	e->t_enter = 0;
	e->cpu = -1;
	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
