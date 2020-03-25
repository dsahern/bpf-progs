// SPDX-License-Identifier: GPL-2.0
/* Track calls to open. Similar to and inspired by opensnoop in bcc-tools.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <linux/list.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "opensnoop.h"
#include "libbpf_helpers.h"
#include "perf_events.h"
#include "timestamps.h"

#include "perf_events.c"

static bool print_time = true;
static bool print_dt;
static bool done;

struct task {
	struct list_head list;
	__u64 time;
	__u32 pid;
	__u32 ppid;
	__u32 flags;
	__u32 mode;
	char comm[TASK_COMM_LEN];
	char *filename;
};

LIST_HEAD(entries);

static void free_task(struct task *task)
{
	list_del(&task->list);
	free(task->filename);
	free(task);
}

static struct task *get_task(struct data *data, bool create)
{
	struct task *task;

	list_for_each_entry(task, &entries, list) {
		if (data->pid == task->pid &&
		    data->ppid == task->ppid)
			return task;
	}

	if (!create)
		return NULL;

	task = calloc(1, sizeof(*task));
	if (task) {
		task->time = data->time;
		task->pid = data->pid;
		task->ppid = data->ppid;
		strcpy(task->comm, data->comm);
		list_add(&task->list, &entries);
	}
	return task;
}

static void print_header(void)
{
	if (print_time)
		printf("%15s", "TIME");
	if (print_dt)
		printf(" %10s", "DT");
	if (print_time || print_dt)
		printf("  ");

	printf("%-16s %6s %6s %8s %8s %6s   %s\n",
	       "COMM", "PID", "PPID", "FLAGS", "MODE", "RET", "FILENAME");
	fflush(stdout);
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

static int print_bpf_output(void *_data, int size)
{
	struct data *data = _data;
	struct task *task;

	task = get_task(data, data->event_type == EVENT_ARG);
	if (!task) {
		printf("Failed to get task entry\n");
		goto out;
	}

	switch (data->event_type) {
	case EVENT_ARG:
		task->filename = strdup(data->filename);
		break;
	case EVENT_RET:
		if (print_time || print_dt)
			show_timestamps(task->time, data->time);
		printf("%-16s %6d %6d %8x %8x %6d   %s\n",
		       task->comm, task->pid, task->ppid, task->flags,
		       task->mode, data->retval, task->filename);
		free_task(task);
		break;
	}

out:
	fflush(stdout);
	return LIBBPF_PERF_EVENT_CONT;
}

static void process_event(struct data *data)
{
	/* nothing to do */
}

static int opensnoop_complete(void)
{
	return done;
}

static void sig_handler(int signo)
{
	printf("Terminating by signal %d\n", signo);
	done = true;
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_KPROBE,
	};
	char *objfile = "opensnoop.o";
	bool filename_set = false;
	const char *probes[] = {
		"do_sys_open",
		NULL
	};
	struct bpf_object *obj;
	int nevents = 1000;

	if (argc > 1) {
		objfile = argv[1];
		filename_set = true;
	}

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

	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
		return 1;

	if (do_kprobe(obj, probes, 0) || do_kprobe(obj, probes, 1))
		return 1;

	if (configure_perf_event_channel(obj, nevents))
		return 1;

	print_header();

	/* main event loop */
	return perf_event_loop(print_bpf_output, NULL, opensnoop_complete);
}
