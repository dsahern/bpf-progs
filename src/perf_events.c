// SPDX-License-Identifier: GPL-2.0
#include <linux/perf_event.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>

#include "linux_utils.h"
#include "perf_events.h"
#include "timestamps.h"

/*
 * time sorted list of events
 */
struct event {
	struct rb_node rb_node;
	struct list_head list;
	__u64 time;
	int cpu;
	int resvd;
	__u8 data[];
};

static struct rb_root events;

static void remove_event(struct event *event)
{
	free(event);
}

static void insert_event(struct perf_event_ctx *ctx, struct event *e_new)
{
	struct rb_root *root = &events;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*node != NULL) {
		struct event *e;

		parent = *node;
		e = container_of(parent, struct event, rb_node);
		if (e->time > e_new->time)
			node = &(*node)->rb_left;
		else if (e->time < e_new->time)
			node = &(*node)->rb_right;
		else {
			if (e->cpu != e_new->cpu) {
				list_add(&e->list, &e_new->list);
			} else {
				free(e_new);
				ctx->time_drops++;
			}
			return;
		}
	}

	rb_link_node(&e_new->rb_node, parent, node);
	rb_insert_color(&e_new->rb_node, root);
}

static void __process_event(struct perf_event_ctx *ctx, struct event *event)
{
	struct event *e, *tmp;

	ctx->process_event(ctx, &event->data);

	list_for_each_entry_safe(e, tmp, &event->list, list) {
		list_del(&e->list);

		ctx->process_event(ctx, &e->data);
		remove_event(e);
	}
}

/* last event seen on this cpu */
static __u64 round_time;

/* mark the start of a round */
static void set_round_time(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		fprintf(stderr, "clock_gettime(CLOCK_MONOTONIC) failed\n");
		return;
	}

	round_time = (__u64) ts_to_ull(&ts);
}

void perf_event_process_events(struct perf_event_ctx *ctx)
{
	__u64 end_time = round_time;
	struct rb_root *rb_root = &events;
	struct rb_node *node;
	struct event *event;

	set_round_time();

	while (1) {
		node = rb_first(rb_root);
		if (!node)
			break;

		event = container_of(node, struct event, rb_node);
		if (event->time >= end_time)
			break;

		rb_erase(&event->rb_node, rb_root);
		__process_event(ctx, event);
		remove_event(event);
	}
}

/*
 * Add event to time sorted backlog queue
 */
static void perf_output_fn(void *_ctx, int cpu, void *_data, __u32 size)
{
	struct perf_event_ctx *ctx = _ctx;
	struct data *data = _data;
	struct event *event;

	if (size < ctx->data_size) {
		fprintf(stderr,
			"Event size %d is less than data size %d\n",
			size, ctx->data_size);
		return;
	}

	event = malloc(sizeof(*event) + ctx->data_size);
	if (!event) {
		fprintf(stderr, "Failed to allocate memory for event\n");
		return;
	}

	INIT_LIST_HEAD(&event->list);

	event->time = ctx->event_timestamp(ctx, data);
	event->cpu = cpu;
	memcpy(&event->data, data, ctx->data_size);
	insert_event(ctx, event);
	ctx->total_events++;
}

int sys_perf_event_open(struct perf_event_attr *attr,
			int cpu, unsigned long flags)
{
	pid_t pid = -1;
	int group_fd = -1;

	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

struct perf_event_sample {
	struct perf_event_header header;
	__u32 size;
	char data[];
};

static void perf_event_lost_fn(void *_ctx, int cpu, __u64 cnt)
{
	struct perf_event_ctx *ctx = _ctx;

	ctx->lost_events++;
}

int perf_event_configure(struct perf_event_ctx *ctx, struct bpf_object *obj,
			 const char *map_name)
{
	struct perf_buffer_opts opts = {
		.sz = sizeof(opts),
		.sample_period = 1,
	};
	struct bpf_map *map;
	int map_fd;

	ctx->num_cpus = get_nprocs() ? : MAX_CPUS;
	if (ctx->num_cpus > MAX_CPUS)
		ctx->num_cpus = MAX_CPUS;

	if (!ctx->page_cnt)
		ctx->page_cnt = 256;  /* pages per mmap */

	if (!ctx->output_fn)
		ctx->output_fn = perf_output_fn;

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		fprintf(stderr, "Failed to get map \"%s\" in obj file\n",
			map_name);
		return 1;
	}

	map_fd = bpf_map__fd(map);

	ctx->pb = perf_buffer__new(map_fd, ctx->page_cnt, ctx->output_fn,
				   perf_event_lost_fn, ctx, &opts);
	return IS_ERR_OR_NULL(ctx->pb) ? 1 : 0;
}

void perf_event_close(struct perf_event_ctx *ctx)
{
	printf("total events: %llu\n", ctx->total_events);
	printf("lost events: %llu\n", ctx->lost_events);
	printf("drops due to time collision: %llu\n", ctx->time_drops);

	perf_buffer__free(ctx->pb);
}

int perf_event_tp_set_prog(int prog_fd, __u64 config)
{
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.type = PERF_TYPE_TRACEPOINT,
		.size = sizeof(attr),
		.wakeup_events = 1, /* get an fd notification for every event */
		.sample_period = 1,
		.config = config,
	};
	int fd, err;

	fd = sys_perf_event_open(&attr, 0, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Failed to open syscall event: %d %s\n",
			fd, strerror(errno));
		return fd;
	}

	err = ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (err) {
		fprintf(stderr, "failed to attach bpf: %d %s\n",
			err, strerror(errno));
		close(fd);
		return -1;
	}

	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

	return fd;
}

static int tp_event_id(const char *event)
{
	char filename[PATH_MAX];
	int fd, n, id = -1;
	char buf[64] = {};

	snprintf(filename, sizeof(filename), "%s/events/%s/id",
		 TRACINGFS, event);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s' to learn id for tracing event '%s'\n",
			filename, event);
		return -1;
	}

	n = read(fd, buf, sizeof(buf)-1);
	if (n < 0) {
		fprintf(stderr, "Failed to read '%s' to learn tracepoint type\n",
			filename);
	} else {
		id = atoi(buf);
	}
	close(fd);

	return id;
}

int tracepoint_perf_event(int prog_fd, const char *name)
{
	int id;

	id = tp_event_id(name);
	if (id < 0)
		return 1;

	return perf_event_tp_set_prog(prog_fd, id);
}

/* tps is a NULL terminated array of tracepoint names.
 * bpf program is expected to be named tracepoint/%s
 */
int configure_tracepoints(struct bpf_object *obj, const char *bpf_fn[],
			  const char *tps[])
{
        struct bpf_program *prog;
        int prog_fd, fd;
        int i;

        for (i = 0; tps[i]; ++i) {
		prog = bpf_object__find_program_by_name(obj, bpf_fn[i]);
		if (!prog) {
			fprintf(stderr,
				"%s: Failed to get prog \"%s\" in obj file\n",
				__func__, bpf_fn[i]);
			return 1;
		}
		prog_fd = bpf_program__fd(prog);

		fd = tracepoint_perf_event(prog_fd, tps[i]);
		if (fd < 0) {
			fprintf(stderr,
				"Failed to create perf_event on %s: %d %s\n",
				tps[i], fd, strerror(errno));
			return 1;
		}
	}

	return 0;
}

/* tps is a NULL terminated array of tracepoint names.
 * bpf program is expected to be named tracepoint/%s
 */
int configure_raw_tracepoints(struct bpf_object *obj, const char *bpf_fn[],
			      const char *tps[])
{
        struct bpf_program *prog;
        int prog_fd, fd;
        int i;

        for (i = 0; tps[i]; ++i) {
		const char *tp;

		prog = bpf_object__find_program_by_name(obj, bpf_fn[i]);
		if (!prog) {
			fprintf(stderr,
				"%s: Failed to get prog \"%s\" in obj file\n",
				__func__, bpf_fn[i]);
			return 1;
		}
		prog_fd = bpf_program__fd(prog);

		/* bpf_raw_tracepoint_open wants basename of tracepoint */
		tp = strchr(tps[i], '/');
		if (tp)
			tp++;
		else
			tp = tps[i];

		fd = bpf_raw_tracepoint_open(tp, prog_fd);
		if (fd < 0) {
			fprintf(stderr,
				"Failed to create perf_event on raw tracepoint %s: %d %s\n",
				tps[i], fd, strerror(errno));
			return 1;
		}
	}

	return 0;
}

/* modern way to do ebpf with kprobe - create the probe
 * with perf_event_open and attach program
 */
int kprobe_perf_event(int prog_fd, const char *func, int retprobe,
		      int attr_type)
{
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.size = sizeof(attr),
		.wakeup_events = 1, /* get an fd notification for every event */
		.sample_period = 1,
		.config = retprobe ? 1ULL : 0, /* 0 for kprobe; 1 for retprobe */
		.kprobe_func = (uint64_t) (unsigned long) func,
		.type = attr_type,
	};
	int fd, err;

	fd = sys_perf_event_open(&attr, 0, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Failed to open kprobe event: %d %s\n",
			fd, strerror(errno));
		return fd;
	}
	err = ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (err) {
		fprintf(stderr, "failed to attach bpf: %d %s\n",
			err, strerror(errno));
		close(fd);
		return -1;
	}

	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

	return fd;
}

static int syscall_event_id(const char *name)
{
	char sysname[PATH_MAX];

	snprintf(sysname, sizeof(sysname), "syscalls/%s", name);

	return tp_event_id(sysname);
}

int perf_event_syscall(int prog_fd, const char *name)
{
	int id;

	id = syscall_event_id(name);
	if (id < 0)
		return 1;

	return perf_event_tp_set_prog(prog_fd, id);
}

void perf_event_loop(struct perf_event_ctx *ctx)
{
	int timeout = 1000;

	for (;;) {
		perf_buffer__poll(ctx->pb, timeout);

		if (ctx->complete_fn && ctx->complete_fn(ctx))
			break;
	}
}
