// SPDX-License-Identifier: GPL-2.0
/* Monitor packet latency. Latency is measured as the time between
 * PTP timestamping in the NIC and handoff to process (currently
 * only users of skb_copy_datagram_iovec - e.g., virtual machines).
 *
 * Data is collected as a histogram per process id with samples
 * exceeding a threshold sent to userspace for further analysis
 * (e.g., to show affected flow).
 *
 * Userspace updates control map with a conversion between ptp
 * and monotonic timestamps (good enough for the purpose at hand)
 * as well threshold for generating samples.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */

#define KBUILD_MODNAME "pktlatency"
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <bpf/bpf_helpers.h>

#include "pktlatency.h"

#include "channel_map.c"

struct bpf_map_def SEC("maps") pktlat_map = {
	.type = BPF_MAP_TYPE_HASH,  // BPF_MAP_TYPE_PERCPU_HASH
	.key_size = sizeof(struct pktlat_hist_key),
	.value_size = sizeof(struct pktlat_hist_val),
	.max_entries = 512,
};

struct bpf_map_def SEC("maps") pktlat_ctl_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct pktlat_ctl),
	.max_entries = 1,
};

static __always_inline int update_stats(struct pktlat_hist_val *hist,
					struct pktlat_ctl *ctl,
					u64 tstamp)
{
	u64 hw_mono, dt, t;

	if (!tstamp) {
		hist->buckets[7]++;
		return 0;
	}

	/* convert ptp time to monotonic */
	if (tstamp > ctl->ptp_ref)
		hw_mono = ctl->mono_ref + (tstamp - ctl->ptp_ref);
	else
		hw_mono = ctl->mono_ref - (ctl->ptp_ref - tstamp);

	t = bpf_ktime_get_ns();
	dt = (t - hw_mono)/1000;

	if (dt <= PKTLAT_BUCKET_0)
		hist->buckets[0]++;
	else if (dt <= PKTLAT_BUCKET_1)
		hist->buckets[1]++;
	else if (dt <= PKTLAT_BUCKET_2)
		hist->buckets[2]++;
	else if (dt <= PKTLAT_BUCKET_3)
		hist->buckets[3]++;
	else if (dt <= PKTLAT_BUCKET_4)
		hist->buckets[4]++;
	else if (dt <= PKTLAT_BUCKET_5)
		hist->buckets[5]++;
	else
		hist->buckets[6]++;

	hist->buckets[8] += dt;

	/* TO-DO: moving average */

	if (ctl->latency_gen_sample && dt > ctl->latency_gen_sample)
		return 1;

	return 0;
}

static __always_inline void gen_sample(struct skb_dg_iov_args *ctx,
				       u64 tstamp, int ifindex, u32 pid,
				       bool with_skb_data)
{
	struct data data;

	memset(&data, 0, sizeof(data));

	data.event_type = EVENT_SAMPLE;
	data.time = bpf_ktime_get_ns();
	data.cpu = (u8) bpf_get_smp_processor_id();

	data.tstamp = tstamp;
	data.ifindex = ifindex;
	data.pid = pid;
	data.pkt_len = ctx->len;

	if (with_skb_data) {
		struct sk_buff *skb = ctx->skbaddr;
		unsigned char *head;
		u16 mac_header;
		u8 *skbdata;

		bpf_probe_read(&data.protocol, sizeof(data.protocol),
				&skb->protocol);

		if (!bpf_probe_read(&head, sizeof(head), &skb->head) &&
		    !bpf_probe_read(&mac_header, sizeof(mac_header),
				    &skb->mac_header)) {
			skbdata = head + mac_header;
			bpf_probe_read(data.pkt_data, sizeof(data.pkt_data), skbdata);
		}
	}

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0) {
	}
}

static __always_inline void get_skb_tstamp(struct sk_buff *skb, u64 *tstamp)
{
	unsigned char *head;
	unsigned int end;

        if (!bpf_probe_read(&head, sizeof(head), &skb->head) &&
            !bpf_probe_read(&end, sizeof(end), &skb->end)) {
		struct skb_shared_hwtstamps *hwtstamp;
		struct skb_shared_info *sh;

		sh = (struct skb_shared_info *) (head + end);
		hwtstamp = &sh->hwtstamps;
		bpf_probe_read(tstamp, sizeof(*tstamp), &hwtstamp->hwtstamp);
	}
}

SEC("tracepoint/skb/skb_copy_datagram_iovec")
int bpf_skb_dg_iov(struct skb_dg_iov_args *ctx)
{
	struct sk_buff *skb = ctx->skbaddr;
	struct pktlat_hist_key hkey = {};
	struct pktlat_hist_val *hist;
	bool with_skb_data = false;
	struct pktlat_ctl *ctl;
	struct net_device *dev;
	int ifindex = -1;
	u64 tstamp = 0;
	u32 key = 0;

	ctl = bpf_map_lookup_elem(&pktlat_ctl_map, &key);
	if (!ctl)
		return 0;

	if (bpf_probe_read(&dev, sizeof(dev), &skb->dev))
		ifindex = -2;
	else if (!dev)
		ifindex = -3;
	else if (bpf_probe_read(&ifindex, sizeof(ifindex), &dev->ifindex))
		ifindex = -4;

	/* this should limit samples to tap devices only */
	if (ifindex < ctl->ifindex_min)
		goto out;

	get_skb_tstamp(skb, &tstamp);

	hkey.pid = (u32) (bpf_get_current_pid_tgid() >> 32);

	hist = bpf_map_lookup_elem(&pktlat_map, &hkey);
	if (hist) {
		if (update_stats(hist, ctl, tstamp))
			with_skb_data = true;
	} else {
		struct pktlat_hist_val hist2;

		memset(&hist2, 0, sizeof(hist2));
		if (update_stats(&hist2, ctl, tstamp))
			with_skb_data = true;
		bpf_map_update_elem(&pktlat_map, &hkey, &hist2, BPF_ANY);
	}

	if ((tstamp && ctl->gen_samples) || with_skb_data)
		gen_sample(ctx, tstamp, ifindex, hkey.pid, with_skb_data);

out:
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int bpf_sched_exit(struct sched_exit_args *ctx)
{
	struct pktlat_hist_key hkey = {
		.pid = (u32)(bpf_get_current_pid_tgid() >> 32),
	};
	struct data data;

	if (!bpf_map_lookup_elem(&pktlat_map, &hkey))
		return 0;

	bpf_map_delete_elem(&pktlat_map, &hkey);

	memset(&data, 0, sizeof(data));
	data.event_type = EVENT_EXIT,
	data.time = bpf_ktime_get_ns();
	data.pid = ctx->pid;
	data.cpu = (u8) bpf_get_smp_processor_id();

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0) {
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
