// SPDX-License-Identifier: GPL-2.0
/* ebpf program on skb/kfree_skb tracepoint. Adds a sample to perf_event
 * buffer for the first 64 bytes of the packet and skb meta-data.
 * Attempts to get namespace from skb device or dst attached to skb.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#define KBUILD_MODNAME "pktdrop"
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/dst.h>
#include <net/net_namespace.h>
#include <bpf/bpf_helpers.h>

#include "pktdrop.h"

#include "channel_map.c"

SEC("tracepoint/skb/kfree_skb")
int bpf_kfree_skb(struct kfree_skb_args *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.event_type = EVENT_SAMPLE,
		.cpu = (u8) bpf_get_smp_processor_id(),
	};
	struct sk_buff *skb = ctx->skbaddr;
	struct net_device *dev;
	u16 mhdr, nhdr, thdr;
	unsigned char *head;
	unsigned int end;
	int ifindex = -1;
	u8 pkt_type;

	data.location = (u64)ctx->location;
	data.protocol = htons(ctx->protocol);

	/* Try to find a net_device. Prefer skb->dev but it gets
	 * dropped at the transport layer.
	 */
	if (bpf_probe_read(&dev, sizeof(dev), &skb->dev) || !dev ||
            bpf_probe_read(&ifindex, sizeof(ifindex), &dev->ifindex)) {
		unsigned long skb_refdst = 0;

		/* fallback to skb_iif which should be set on ingress */
		if (bpf_probe_read(&ifindex, sizeof(ifindex), &skb->skb_iif))
			ifindex = -1;

		if (!bpf_probe_read(&skb_refdst, sizeof(skb_refdst),
				    &skb->_skb_refdst) && skb_refdst) {
			struct dst_entry *dst;

			dst = (struct dst_entry *)(skb_refdst & SKB_DST_PTRMASK);
			bpf_probe_read(&dev, sizeof(dev), &dst->dev);
		}
	}

	data.ifindex = ifindex;

	/* assumes network namespaces enabled */
	if (dev)
		bpf_probe_read(&data.netns, sizeof(data.netns), &dev->nd_net);

	bpf_probe_read(&data.pkt_len, sizeof(data.pkt_len), &skb->len);
	if (!bpf_probe_read(&pkt_type, sizeof(pkt_type), &skb->__pkt_type_offset))
		data.pkt_type = pkt_type & 7;

	if (!bpf_probe_read(&head, sizeof(head), &skb->head) &&
	    !bpf_probe_read(&mhdr, sizeof(mhdr), &skb->mac_header) &&
	    !bpf_probe_read(&nhdr, sizeof(nhdr), &skb->network_header) &&
	    !bpf_probe_read(&thdr, sizeof(thdr), &skb->transport_header)) {
		u8 *skbdata = head + mhdr;

		data.pkt_len += nhdr + thdr;
		bpf_probe_read(data.pkt_data, sizeof(data.pkt_data), skbdata);
	}

	/* get frags and gso size information if possible. Based on
	 * the expansion of skb_shinfo(skb) which relies on
	 * skb_end_pointer which is a function of BITS_PER_LONG. This
	 * expansion is for 64-bit.
	 */
	if (!bpf_probe_read(&end, sizeof(end), &skb->end)) {
		struct skb_shared_info *sh;

		sh = (struct skb_shared_info *) (head + end);
		bpf_probe_read(&data.nr_frags, sizeof(data.nr_frags),
				   &sh->nr_frags);

		bpf_probe_read(&data.gso_size, sizeof(data.gso_size),
			       &sh->gso_size);
	}

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0) {
	}

	return 0;
}

/* capture network namespace delete */
SEC("kprobe/fib_net_exit")
int bpf_fib_net_exit(struct pt_regs *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.event_type = EVENT_EXIT,
		.cpu = (u8) bpf_get_smp_processor_id(),
	};
	struct net *net = (struct net *)ctx->di;

	if (net) {
		data.netns = ctx->di;

		if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
					  &data, sizeof(data)) < 0) {
		}
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
