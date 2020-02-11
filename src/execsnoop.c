// SPDX-License-Identifier: GPL-2.0
/* Track calls to exec. Similar to and inspired by execsnoop in bcc-tools.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
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

	u64 time;
	u32 pid;
	u32 ppid;
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
	u32 pid = data->pid;
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

static void show_timestamps(u64 start, u64 end)
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

static int do_execve_kprobes(struct bpf_object *obj)
{
	struct bpf_program *prog;
	int prog_fd, fd;

	/*
	 * create kprobe on __x64_sys_execve and install bpf program
	 */
	prog = bpf_object__find_program_by_title(obj, "kprobe/execve");
	if (!prog) {
		printf("Failed to get prog in obj file\n");
		return 1;
	}

	prog_fd = bpf_program__fd(prog);
	fd = kprobe_perf_event(prog_fd, "__x64_sys_execve", 0, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to create probe on __x64_sys_execve: %d %s\n",
			fd, strerror(errno));
		return 1;
	}

	/*
	 * create return kprobe on __x64_sys_execve and install bpf program
	 */
	prog = bpf_object__find_program_by_title(obj, "kprobe/execve_ret");
	if (prog) {
		prog_fd = bpf_program__fd(prog);
		fd = kprobe_perf_event(prog_fd, "__x64_sys_execve", 0, 1);
		if (fd < 0) {
			fprintf(stderr, "Failed to create return probe on __x64_sys_execve: %d %s\n",
				fd, strerror(errno));
			return 1;
		}
	}

	return 0;
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
	char *objfile = "execsnoop.o";
	struct bpf_prog_load_attr prog_load_attr = {};
	const char *tps[] = {
		"sched/sched_process_exit",
		NULL
	};
	bool filename_set = false;
	struct bpf_object *obj;
	int nevents = 100;
	int rc;

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

	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
		return 1;

	if (do_execve_kprobes(obj) || do_tracepoint(obj, tps))
		return 1;

	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		perror("signal");
		return 1;
	}

	setlinebuf(stdout);
	setlinebuf(stderr);

	if (configure_perf_event_channel(obj, nevents))
		return 1;

	print_header();

	/* main event loop */
	return perf_event_loop(print_bpf_output, NULL, execsnoop_complete);
}
