// SPDX-License-Identifier: GPL-2.0
/* Track calls to exec. Similar to and inspired by execsnoop in bcc-tools.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#include <stdbool.h>
#include <linux/bpf.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "execsnoop.h"
#include "libbpf_helpers.h"
#include "perf_events.h"
#include "kprobes.h"
#include "timestamps.h"
#include "tasks.h"

static bool print_time = true;
static bool print_dt;
static bool success_only = true;
static bool done;
static unsigned int verbose;

struct exec_task_priv {
	__u64 time;
	int narg;
	char *arg[MAXARG + 1];
};

static void exec_task_cleanup(struct task *task)
{
	struct exec_task_priv *priv = task_priv(task);
	int i;

	for (i = 0; i < priv->narg; ++i) {
		free(priv->arg[i]);
		priv->arg[i] = NULL;
	}
}

static void print_header(void)
{
	if (print_time)
		printf("%15s", "TIME");
	if (print_dt)
		printf(" %10s", "DT");
	if (print_time || print_dt)
		printf("  ");
	printf("%4s %6s %6s %6s   %s\n", "CPU", "PPID", "PID", "RET", "COMM");
}

static void show_timestamps(__u64 start, __u64 end)
{
	char buf[64];

	if (print_time)
		printf("%15s", timestamp(buf, sizeof(buf), start));

	if (print_dt)
		print_time_usecs(end - start);

	printf("  ");
}

static const char *event_names[EVENT_MAX] = { "start", "arg", "ret", "exit" };

static __u64 event_timestamp(struct perf_event_ctx *ctx, void *_data)
{
	struct data *data = _data;

	return data->time;
}

static void process_event(struct perf_event_ctx *ctx, void *_data)
{
	struct data *data = _data;
	struct exec_task_priv *priv;
	struct task *task;
	int i;

	if (verbose)
		printf("%llu [%02d] event %s proc %s %d/%d comm %s arg %s data %px\n",
			data->time, data->cpu, event_names[data->event_type],
			data->comm, data->tid, data->pid,
			data->comm, data->arg, data);

	if (data->event_type == EVENT_START) {
		task = task_add(data->comm, data->pid, data->tid, data->ppid,
				sizeof(struct exec_task_priv), NULL, NULL,
				exec_task_cleanup);
	} else {
		task = task_find(data->pid, data->tid);
	}

	if (!task) {
		if (data->event_type != EVENT_EXIT && verbose) {
			fprintf(stderr,
				"Failed to get task entry for event %s: %s %d %d\n",
				event_names[data->event_type],
				data->comm, data->tid, data->pid);
		}
		return;
	}

	priv = task_priv(task);

	switch (data->event_type) {
	case EVENT_START:
		for (i = 0; i < priv->narg; ++i) {
			free(priv->arg[i]);
			priv->arg[i] = NULL;
		}
		priv->time = data->time;

		if (*data->arg)
			priv->arg[0] = strdup(data->arg);
		else
			priv->arg[0] = strdup("<unknown>");
		priv->narg = 1;
		break;
	case EVENT_ARG:
		i = priv->narg;
		if (*data->arg)
			priv->arg[i] = strdup(data->arg);
		else
			priv->arg[i] = strdup("<unknown>");
		priv->narg++;
		break;
	case EVENT_RET:
		if (!success_only || data->retval == 0) {
			if (print_time || print_dt)
				show_timestamps(priv->time, data->time);
			printf("[%02u] %6d %6d/%-6d %6d   %s ->",
			       data->cpu, task->ppid, task->tid, task->pid,
			       data->retval, task->comm);

			for (i = 0; i < priv->narg; ++i)
				printf(" %s", priv->arg[i]);
			printf("\n");
		}
		if (data->retval)
			task_remove(data->pid, data->tid);
		break;
	case EVENT_EXIT:
		if (print_time || print_dt)
			show_timestamps(priv->time, data->time);
		printf("[%02u] %6d %6d/%-6d %6s   %s [EXIT]\n",
		       data->cpu, task->ppid, task->tid, task->pid,
		       "", task->comm);
		task_remove(data->pid, data->tid);
	}
}

static int execsnoop_complete(struct perf_event_ctx *ctx)
{
	perf_event_process_events(ctx);
	return done;
}

static void sig_handler(int signo)
{
	printf("Terminating by signal %d\n", signo);
	done = true;
}

static void print_usage(char *prog)
{
	printf(
	"usage: %s OPTS\n\n"
	"	-f bpf-file    bpf filename to load\n"
	"	-s             use syscall tracepoints instead of kprobes\n"
	"	-v             enable verbose logging\n"
	"	-T             do not show timestamps (default on)\n"
	"	-D             show syscall time (default off)\n"
	"	-A             show all execs (default only successful exec)\n"
	, basename(prog));
}

int main(int argc, char **argv)
{
	struct kprobe_data probes[] = {
		{ .prog = "bpf_sys_execve",     .func = "__x64_sys_execve",
		  .fd = -1 },
		{ .prog = "bpf_sys_execve_ret", .func = "__x64_sys_execve",
		  .fd = -1, .retprobe = true },
	};
	const char *bpf_fn_exec[] = {
		"bpf_sys_enter_execve",
		"bpf_sys_exit_execve",
		NULL
	};
	const char *tp_exec[] = {
		"syscalls/sys_enter_execve",
		"syscalls/sys_exit_execve",
		NULL
	};
	const char *bpf_fn[] = {
		"bpf_sched_exit",
		NULL
	};
	const char *tp[] = {
		"sched/sched_process_exit",
		NULL
	};
	struct perf_event_ctx ctx = {
		.event_timestamp = event_timestamp,
		.process_event = process_event,
		.complete_fn = execsnoop_complete,
		.data_size = sizeof(struct data),
	};
	char *objfile = "execsnoop.o";
	bool filename_set = false;
	bool use_kprobe = true;
	struct bpf_object *obj;
	int rc;

	while ((rc = getopt(argc, argv, "f:svTDA")) != -1)
	{
		switch(rc) {
		case 'f':
			objfile = optarg;
			filename_set = true;
			break;
		case 's':
			use_kprobe = false;
			break;
		case 'v':
			verbose++;
			break;
		case 'T':
			print_time = false;
			break;
		case 'D':
			print_dt = true;
			break;
		case 'A':
			success_only = false;
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	task_init();

	if (set_reftime())
		return 1;

	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		perror("signal");
		return 1;
	}

	setlinebuf(stdout);
	setlinebuf(stderr);

	if (load_obj_file(objfile, filename_set, &obj))
		return 1;

	rc = 1;
	if (use_kprobe) {
		if (kprobe_init(obj, probes, ARRAY_SIZE(probes)))
			goto out;
	} else if (configure_tracepoints(obj, bpf_fn_exec, tp_exec)) {
		goto out;
	}

	if (configure_tracepoints(obj, bpf_fn, tp))
		goto out;

	if (perf_event_configure(&ctx, obj, "channel"))
		goto out;

	print_header();

	/* main event loop */
	perf_event_loop(&ctx, 1000);
	rc = 0;

	task_cleanup();
out:
	perf_event_close(&ctx);
	kprobe_cleanup(probes, ARRAY_SIZE(probes));

	return rc;
}
