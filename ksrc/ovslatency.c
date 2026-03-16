// SPDX-License-Identifier: GPL-2.0
/* Track latency induced by OVS.
 *
 * Copyright (c) 2020 David Ahern <dsahern@gmail.com>
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "ovslatency.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct ovslat_hist_val);
} ovslat_map SEC(".maps");

struct ovs_enter {
	u64 t_enter;
	void *skb;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct ovs_enter);
} ovs_enter_map SEC(".maps");

SEC("kprobe/ovs_vport_receive")
int bpf_ovs_kprobe(struct pt_regs *ctx)
{
	struct ovs_enter *e;
	u32 idx = 0;

	e = bpf_map_lookup_elem(&ovs_enter_map, &idx);
	if (e) {
		e->t_enter = bpf_ktime_get_ns();
		e->skb = (void *)PT_REGS_PARM1(ctx);
	}

	return 0;
}

SEC("kprobe/ovs_vport_receive_ret")
int bpf_ovs_kprobe_ret(struct pt_regs *ctx)
{
	struct ovs_enter *e;
	u32 idx = 0;

	e = bpf_map_lookup_elem(&ovs_enter_map, &idx);
	if (!e)
		goto out;

	if (e->t_enter) {
		struct ovslat_hist_val *hist;
		u64 t = bpf_ktime_get_ns();
		u64 dt = (t - e->t_enter) / 1000;  /* nsec to usec */

		hist = bpf_map_lookup_elem(&ovslat_map, &idx);
		if (hist) {
			u64 *c;

			__sync_fetch_and_add(&hist->buckets[7], 1);

			/* update hist entry */
			if (dt <= OVS_BUCKET_0)
				c = &hist->buckets[0];
			else if (dt <= OVS_BUCKET_1)
				c = &hist->buckets[1];
			else if (dt <= OVS_BUCKET_2)
				c = &hist->buckets[2];
			else if (dt <= OVS_BUCKET_3)
				c = &hist->buckets[3];
			else if (dt <= OVS_BUCKET_4)
				c = &hist->buckets[4];
			else if (dt <= OVS_BUCKET_5)
				c = &hist->buckets[5];
			else
				c = &hist->buckets[6];

			__sync_fetch_and_add(c, 1);
		}
	}
	e->t_enter = 0;
	e->skb = NULL;
out:
	return 0;
}

char _license[] SEC("license") = "GPL";
