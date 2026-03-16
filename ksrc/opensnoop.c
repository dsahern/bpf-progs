// SPDX-License-Identifier: GPL-2.0
/* Entry and return robes on do_sys_open to track file opens
 * by processes. Data sent to userspace using perf_events
 * and channel map.
 *
 * David Ahern <dsahern@gmail.com>
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "opensnoop.h"
#include "set_current_info.c"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, int);
	__type(value, __u32);
} channel SEC(".maps");

SEC("kprobe/do_sys_open")
int bpf_sys_open(struct pt_regs *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.cpu = (u8) bpf_get_smp_processor_id(),
		.event_type = EVENT_ARG,
	};
	char *filename = (char *)PT_REGS_PARM2(ctx);
	unsigned long flags = PT_REGS_PARM3(ctx);
	unsigned long mode = PT_REGS_PARM4(ctx);

	set_current_info(&data);

	bpf_probe_read_str(data.filename, sizeof(data.filename), filename);
	data.flags = (u32) flags;
	data.mode = (u32) mode;

	bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
			      &data, sizeof(data));

	return 0;
}

SEC("kprobe/do_sys_open_ret")
int bpf_sys_open_ret(struct pt_regs *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.cpu = (u8) bpf_get_smp_processor_id(),
		.event_type = EVENT_RET,
		.retval = ctx->ax
	};

	set_current_info(&data);

	bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
			      &data, sizeof(data));

	return 0;
}

char _license[] SEC("license") = "GPL";
