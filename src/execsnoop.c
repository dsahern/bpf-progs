// SPDX-License-Identifier: GPL-2.0
/* Track calls to exec. Similar to and inspired by execsnoop in bcc-tools.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/rbtree.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "execsnoop.h"
#include "libbpf_helpers.h"
#include "perf_events.h"
#include "timestamps.h"

#include "perf_events.c"

static bool print_time = true;
static bool print_dt;
static bool success_only = true;
static bool done;

struct task {
	struct rb_node rb_node;

	__u64 time;
	__u32 pid;
	__u32 ppid;
	char comm[TASK_COMM_LEN];
	int narg;
	char *arg[MAXARG + 1];
};

static struct rb_root all_tasks;

static void remove_task(struct task *task)
{
	int i;

	rb_erase(&task->rb_node, &all_tasks);

	for (i = 0; i < task->narg; ++i)
		free(task->arg[i]);

	free(task);
}

static int insert_task(struct rb_root *root, struct task *new_task)
{
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*node != NULL) {
		struct task *task;

		parent = *node;
		task = container_of(parent, struct task, rb_node);
		if (task->pid > new_task->pid)
			node = &(*node)->rb_left;
		else if (task->pid < new_task->pid)
			node = &(*node)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&new_task->rb_node, parent, node);
	rb_insert_color(&new_task->rb_node, root);

	return 0;
}

static struct task *get_task(struct data *data, bool create)
{
	struct rb_node **p = &all_tasks.rb_node;
	struct rb_node *parent = NULL;
	__u32 pid = data->pid;
	struct task *task;

	while (*p != NULL) {
		parent = *p;

		task = container_of(parent, struct task, rb_node);
		if (task->pid > pid)
			p = &(*p)->rb_left;
		else if (task->pid < pid)
			p = &(*p)->rb_right;
		else
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

		if (insert_task(&all_tasks, task)) {
			free(task);
			task = NULL;
		}
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

static const char *event_names[] = { "start", "arg", "ret", "exit" };

static int print_bpf_output(void *_data, int size)
{
	struct data *data = _data;
	struct task *task;
	int i;

	task = get_task(data, data->event_type == EVENT_START);
	if (!task) {
		if (data->event_type != EVENT_EXIT) {
			fprintf(stderr,
				"Failed to get task entry for event %s: %s %d %d\n",
				event_names[data->event_type],
				data->comm, data->pid, data->ppid);
		}
		goto out;
	}

	switch (data->event_type) {
	case EVENT_START:
		for (i = 0; i < task->narg; ++i)
			free(task->arg[i]);

		if (data->arg)
			task->arg[0] = strdup(data->arg);
		else
			task->arg[0] = strdup("<unknown>");
		task->narg = 1;
		break;
	case EVENT_ARG:
		i = task->narg;
		if (data->arg)
			task->arg[i] = strdup(data->arg);
		else
			task->arg[i] = strdup("<unknown>");
		task->narg++;
		break;
	case EVENT_RET:
		if (!success_only || data->retval == 0) {
			if (print_time || print_dt)
				show_timestamps(task->time, data->time);
			printf("[%02u] %6d %6d %6d   %s ->",
			       data->cpu, task->ppid, task->pid, data->retval, task->comm);

			for (i = 0; i < task->narg; ++i)
				printf(" %s", task->arg[i]);
			printf("\n");
		}
		if (data->retval)
			remove_task(task);
		break;
	case EVENT_EXIT:
		if (print_time || print_dt)
			show_timestamps(task->time, data->time);
		printf("[%02u] %6d %6d %6s   %s [EXIT]\n",
		       data->cpu, task->ppid, task->pid, "", data->comm);
		remove_task(task);
	}

out:
	return LIBBPF_PERF_EVENT_CONT;
}

static void process_event(struct data *data)
{
	/* nothing to do */
}

static int execsnoop_complete(void)
{
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
	"	-T             do not show timestamps (default on)\n"
	"	-D             show syscall time (default off)\n"
	"	-A             show all execs (default only successful exec)\n"
	, basename(prog));
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {};
	struct kprobe_data probes[] = {
		{ .prog = "kprobe/execve",     .func = "__x64_sys_execve",
		  .fd = -1 },
		{ .prog = "kprobe/execve_ret", .func = "__x64_sys_execve",
		  .fd = -1, .retprobe = true },
	};
	const char *tps[] = {
		"sched/sched_process_exit",
		NULL
	};
	char *objfile = "execsnoop.o";
	bool filename_set = false;
	struct bpf_object *obj;
	int nevents = 100;
	int attr_type;
	int rc;

	attr_type = kprobe_event_type();
	if (attr_type < 0) {
		/* SWAG - allows execsnoop to work on 4.14 and 5.4 */
		probes[0].func = "sys_execve";
		probes[1].func = "sys_execve";
		objfile = "execsnoop_legacy.o";
	}

	while ((rc = getopt(argc, argv, "f:TDA")) != -1)
	{
		switch(rc) {
		case 'f':
			objfile = optarg;
			filename_set = true;
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

	rc = 1;
	if (kprobe_init(obj, probes, ARRAY_SIZE(probes)) ||
	    do_tracepoint(obj, tps))
		goto out;

	if (configure_perf_event_channel(obj, nevents))
		goto out;

	print_header();

	/* main event loop */
	rc = perf_event_loop(print_bpf_output, NULL, execsnoop_complete);
out:
	close_perf_event_channel();
	kprobe_cleanup(probes, ARRAY_SIZE(probes));

	return rc;
}
