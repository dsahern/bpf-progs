// SPDX-License-Identifier: GPL-2.0
/* Snoop process exec(). Inspired by execsnoop.py from bcc repository
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
	void *pfilename = (void *)(ctx->di + offsetof(struct pt_regs, di));
	void *pargv = (void *)(ctx->di + offsetof(struct pt_regs, si));
	char *filename, **argv;
	bool bail = false;
	int i;

	set_current_info(&data);

	if (bpf_probe_read(&filename, sizeof(filename), pfilename) ||
	    bpf_probe_read_str(data.arg, sizeof(data.arg)-1, filename) < 0) {
		__builtin_strcpy(data.arg, "<filename FAILED>");
		bail = true;
	}

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0 || bail)
		goto out;

	data.event_type = EVENT_ARG;
	if (bpf_probe_read((void *) &argv, sizeof(void *), pargv))
		goto out;

	/* skip first arg; submitted filename */
	#pragma unroll
	for (int i = 1; i <= MAXARG; i++) {
		void *ptr = NULL;

		if (bpf_probe_read(&ptr, sizeof(ptr), &argv[i]) || ptr == NULL)
			goto out;
		if (bpf_probe_read_str(data.arg, sizeof(data.arg)-1, ptr) < 0)
			goto out;

		/* give each event a different timestamp */
		data.time++;
		if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
					  &data, sizeof(data)) < 0)
			goto out;
	}

	__builtin_strcpy(data.arg, "...");
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

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_sys_enter_execve(struct execve_enter_args *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.cpu = (u8) bpf_get_smp_processor_id(),
		.event_type = EVENT_START
	};
	int i;

	set_current_info(&data);

	if (bpf_probe_read_str(data.arg, sizeof(data.arg), ctx->filename) < 0)
		__builtin_strcpy(data.arg, "<filename FAILED>");

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0)
		goto out;

	data.event_type = EVENT_ARG;

	/* skip first arg; submitted filename */
	#pragma unroll
	for (int i = 1; i <= MAXARG; i++) {
		void *ptr = NULL;

		if (bpf_probe_read(&ptr, sizeof(ptr), &ctx->argv[i]))
			goto out;
		if (ptr == NULL)
			goto out;
		if (bpf_probe_read_user_str(data.arg, sizeof(data.arg), ptr) < 0)
			goto out;
		if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
					  &data, sizeof(data)) < 0)
			goto out;
	}

	__builtin_strcpy(data.arg, "...");
	bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
			      &data, sizeof(data));
out:
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int bpf_sys_exit_execve(struct execve_exit_args *ctx)
{
	struct data data = {
		.time = bpf_ktime_get_ns(),
		.cpu = (u8) bpf_get_smp_processor_id(),
		.event_type = EVENT_RET,
		.retval = ctx->ret,
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

	__builtin_memcpy(data.comm, ctx->comm, 15);
	data.pid = ctx->pid;

	if (bpf_perf_event_output(ctx, &channel, BPF_F_CURRENT_CPU,
				  &data, sizeof(data)) < 0) {
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
int _version SEC("version") = LINUX_VERSION_CODE;
