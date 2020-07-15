// SPDX-License-Identifier: GPL-2.0
/* Dummy XDP program
 *
 * David Ahern <dsahern@gmail.com>
 */
#define KBUILD_MODNAME "xdp_dummy"
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_dummy")
int xdp_dummy_prog(struct xdp_md *ctx)
{
	//bpf_debug("ingress: device %u queue %u\n",
	//	      ctx->ingress_ifindex, ctx->rx_queue_index);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
