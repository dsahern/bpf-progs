// SPDX-License-Identifier: GPL-2.0
/* perf_event_poller_multi and related functions and structures are based
 * on tools/testing/selftests/bpf/trace_helpers.c from around the v5.3
 * kernel and then adapted to the needs of the commands in this repo.
 *
 * Rest of the functions were added for time sorting perf events across
 * cpus, and helpers developed as common code across various commands.
 */
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

#include "perf_events.h"
#include "timestamps.h"

/*
 * time sorted list of events
 */
struct event {
	struct rb_node rb_node;
	struct list_head list;
	__u64 time;
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
			free(e_new);
			ctx->time_drops++;
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

	if (event->list.prev == event->list.next)
		return;

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
static int __handle_bpf_output(struct perf_event_ctx *ctx, void *_data, int size)
{
	struct data *data = _data;
	struct event *event;

	if (size < ctx->data_size) {
		fprintf(stderr,
			"Event size %d is less than data size %d\n",
			size, ctx->data_size);
		return LIBBPF_PERF_EVENT_ERROR;
	}

	event = malloc(sizeof(*event) + ctx->data_size);
	if (!event) {
		fprintf(stderr, "Failed to allocate memory for event\n");
		return LIBBPF_PERF_EVENT_ERROR;
	}
	INIT_LIST_HEAD(&event->list);

	event->time = ctx->event_timestamp(ctx, data);
	memcpy(&event->data, data, ctx->data_size);
	insert_event(ctx, event);
	ctx->total_events++;

	return LIBBPF_PERF_EVENT_CONT;
}

int sys_perf_event_open(struct perf_event_attr *attr,
			int cpu, unsigned long flags)
{
	pid_t pid = -1;
	int group_fd = -1;

	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int perf_event_mmap_header(struct perf_event_ctx *ctx, int fd,
				  struct perf_event_mmap_page **header)
{
	void *base;
	int mmap_size;

	ctx->page_size = getpagesize();
	mmap_size = ctx->page_size * (ctx->page_cnt + 1);

	base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		fprintf(stderr, "mmap err\n");
		return -1;
	}

	*header = base;
	return 0;
}

struct perf_event_sample {
	struct perf_event_header header;
	__u32 size;
	char data[];
};

static enum bpf_perf_event_ret
bpf_perf_event_print(struct perf_event_header *hdr, void *private_data)
{
	struct perf_event_sample *e = (struct perf_event_sample *)hdr;
	struct perf_event_ctx *ctx = private_data;
	int ret;

	if (e->header.type == PERF_RECORD_SAMPLE) {
		ret = ctx->output_fn(ctx, e->data, e->size);
		if (ret != LIBBPF_PERF_EVENT_CONT)
			return ret;
	} else if (e->header.type == PERF_RECORD_LOST) {
		struct {
			struct perf_event_header header;
			__u64 id;
			__u64 lost;
		} *lost = (void *) e;
		fprintf(stderr, "lost %lld events\n", lost->lost);
	} else {
		fprintf(stderr, "unknown event type=%d size=%d\n",
		       e->header.type, e->header.size);
	}

	return LIBBPF_PERF_EVENT_CONT;
}

static int perf_event_poller_multi(struct perf_event_ctx *ctx)
{
	enum bpf_perf_event_ret ret = LIBBPF_PERF_EVENT_DONE;
	int page_size = ctx->page_size;
	int page_cnt = ctx->page_cnt;
	struct pollfd *pfds;
	int timeout = 1000;
	void *buf = NULL;
	size_t len = 0;
	int i;

	pfds = calloc(ctx->num_cpus, sizeof(*pfds));
	if (!pfds)
		return LIBBPF_PERF_EVENT_ERROR;

	for (i = 0; i < ctx->num_cpus; i++) {
		pfds[i].fd = ctx->pmu_fds[i];
		pfds[i].events = POLLIN;
	}

	for (;;) {
		poll(pfds, ctx->num_cpus, timeout);

		if (ctx->start_fn)
			ctx->start_fn();

		for (i = 0; i < ctx->num_cpus; i++) {
			ret = bpf_perf_event_read_simple(ctx->headers[i],
							 page_cnt * page_size,
							 page_size, &buf, &len,
							 bpf_perf_event_print,
							 ctx);
			if (ret != LIBBPF_PERF_EVENT_CONT)
				break;
		}

		if (ctx->complete_fn && ctx->complete_fn(ctx))
			break;
	}
	free(buf);
	free(pfds);

	return ret;
}

static int perf_event_output(struct perf_event_ctx *ctx, int map_fd,
			     int nevents)
{
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.size = sizeof(attr),
		.wakeup_events = nevents, /* get an fd notification for every event */
	};
	int i;

	for (i = 0; i < ctx->num_cpus; i++) {
		int key = i;

		ctx->pmu_fds[i] = sys_perf_event_open(&attr, i, 0);
		if (ctx->pmu_fds[i] < 0) {
			fprintf(stderr, "sys_perf_event_open failed: %d: %s\n",
				errno, strerror(errno));
			return -1;
		}
		if (bpf_map_update_elem(map_fd, &key, &ctx->pmu_fds[i], BPF_ANY)) {
			fprintf(stderr, "bpf_map_update_elem failed\n");
			return -1;
		}
		ioctl(ctx->pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
	}

	return 0;
}

int perf_event_configure(struct perf_event_ctx *ctx, struct bpf_object *obj,
			 const char *map_name, int nevents)
{
	struct bpf_map *map;
	int map_fd, i;

	ctx->num_cpus = get_nprocs() ? : MAX_CPUS;
	if (ctx->num_cpus > MAX_CPUS)
		ctx->num_cpus = MAX_CPUS;

	ctx->page_size = getpagesize();

	if (!ctx->page_cnt)
		ctx->page_cnt = 256;  /* pages per mmap */

	ctx->pmu_fds = calloc(ctx->num_cpus, sizeof(int));
	if (!ctx->pmu_fds) {
		fprintf(stderr, "Failed to allocate memory for pmu fds\n");
		return 1;
	}

	ctx->headers = calloc(ctx->num_cpus, sizeof(struct perf_event_mmap_page *));
	if (!ctx->headers) {
		fprintf(stderr, "Failed to allocate memory for mmap_page\n");
		goto err_out;
	}

	if (!ctx->output_fn)
		ctx->output_fn = __handle_bpf_output;

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		fprintf(stderr, "Failed to get map in obj file\n");
		goto err_out;
	}

	map_fd = bpf_map__fd(map);

	if (perf_event_output(ctx, map_fd, nevents))
		goto err_out;

	for (i = 0; i < ctx->num_cpus; i++) {
		int err;

		err = perf_event_mmap_header(ctx, ctx->pmu_fds[i],
					     &ctx->headers[i]);
		if (err < 0)
			goto err_out;
	}

	return 0;
err_out:
	free(ctx->pmu_fds);
	free(ctx->headers);
	return 1;
}

void perf_event_close(struct perf_event_ctx *ctx)
{
	int i;

	printf("total events: %llu\n", ctx->total_events);
	printf("drops due to time collision: %llu\n", ctx->time_drops);

	for (i = 0; i < ctx->num_cpus; i++) {
		ioctl(ctx->pmu_fds[i], PERF_EVENT_IOC_DISABLE, 0);
		close(ctx->pmu_fds[i]);
	}

	free(ctx->pmu_fds);
	free(ctx->headers);
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
int configure_tracepoints(struct bpf_object *obj, const char *tps[])
{
        struct bpf_program *prog;
        int prog_fd, fd;
        int i;

        for (i = 0; tps[i]; ++i) {
                char buf[256];

                snprintf(buf, sizeof(buf), "tracepoint/%s", tps[i]);

		prog = bpf_object__find_program_by_title(obj, buf);
		if (!prog) {
			printf("Failed to get prog in obj file\n");
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
int configure_raw_tracepoints(struct bpf_object *obj, const char *tps[])
{
        struct bpf_program *prog;
        int prog_fd, fd;
        int i;

        for (i = 0; tps[i]; ++i) {
		const char *tp;
                char buf[256];

		snprintf(buf, sizeof(buf), "raw_tracepoint/%s", tps[i]);

		prog = bpf_object__find_program_by_title(obj, buf);
		if (!prog) {
			printf("Failed to get prog in obj file\n");
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

int perf_event_loop(struct perf_event_ctx *ctx)
{
	return perf_event_poller_multi(ctx);
}
