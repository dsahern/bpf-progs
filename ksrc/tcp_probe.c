#define KBUILD_MODNAME "tcp_probe"
#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

#include "tcp_probe.h"

#include "channel_map.c"

SEC("tracepoint/tcp/tcp_probe")
int bpf_tcp_probe(struct tcp_probe_args *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.cpu = bpf_get_smp_processor_id(),
	};

	memcpy(&data.s_addr, &ctx->s_addr, sizeof(struct sockaddr_in6));
	memcpy(&data.d_addr, &ctx->d_addr, sizeof(struct sockaddr_in6));
	data.mark = ctx->mark;
	data.data_len = ctx->data_len;
	data.snd_nxt = ctx->snd_nxt;
	data.snd_una = ctx->snd_una;
	data.snd_cwnd = ctx->snd_cwnd;
	data.ssthresh = ctx->ssthresh;
	data.snd_wnd = ctx->snd_wnd;
	data.srtt = ctx->srtt;
	data.rcv_wnd = ctx->rcv_wnd;

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0) {
		// TO-DO: track number of failed writes?
		//        bpf printk??
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
