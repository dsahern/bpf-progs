// SPDX-License-Identifier: GPL-2.0
/* Snoop process exec(). Inspired by execsnoop.py from bcc repository
 * Version works on older kernels ... e.g., 4.14
 *
 * David Ahern <dsahern@gmail.com>
 */

#define KBUILD_MODNAME "execsnoop"
#include <linux/ptrace.h>  /* pt_regs via asm/ptrace.h */
#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

#include "execsnoop.h"
#include "sched_tp.h"

#include "channel_map.c"
#include "set_current_info.c"

/* expecting args to be filename, argv, envp */
SEC("kprobe/execve")
int bpf_sys_execve(struct pt_regs *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.cpu = (u8) bpf_get_smp_processor_id(),
		.event_type = EVENT_START
	};
	void *filename = (void *)ctx->di;
	void **argv = (void **)ctx->si;
	bool bail = false;
	int i;

	set_current_info(&data);

	if (bpf_probe_read_str(data.arg, sizeof(data.arg), filename) < 0) {
		strcpy(data.arg, "<filename FAILED>");
		bail = true;
	}

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0 || bail)
		goto out;

	data.event_type = EVENT_ARG;

	/* skip first arg; submitted filename */
	#pragma unroll
	for (int i = 1; i <= MAXARG; i++) {
		void *ptr = NULL;

		if (bpf_probe_read(&ptr, sizeof(ptr), &argv[i]) || ptr == NULL)
			goto out;
		if (bpf_probe_read_str(data.arg, sizeof(data.arg), ptr) < 0)
			goto out;
		if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
					  &data, sizeof(data)) < 0)
			goto out;
	}

	strcpy(data.arg, "...");
	bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
			      &data, sizeof(data));
out:
	return 0;
}

SEC("kprobe/execve_ret")
int bpf_sys_execve_ret(struct pt_regs *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.cpu = (u8) bpf_get_smp_processor_id(),
		.event_type = EVENT_RET,
		.retval = ctx->ax,
	};

	set_current_info(&data);

	bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
			  &data, sizeof(data));

	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int bpf_sched_exit(struct sched_exit_args *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.cpu = (u8) bpf_get_smp_processor_id(),
		.event_type = EVENT_EXIT,
	};

	memcpy(data.comm, ctx->comm, 15);
	data.pid = ctx->pid;

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0) {
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
