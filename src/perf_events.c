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
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>

#include "perf_events.h"

static const char *tracingfs = "/sys/kernel/debug/tracing";
static int numcpus;
static int page_size;
static int page_cnt = 256;  /* pages per mmap */
static __u64 total_events;
static __u64 time_drops;

/* users of the generic caching API are expected to implement
 * process_event.
 */
static void process_event(struct data *data);

static int pmu_fds[MAX_CPUS];
static struct perf_event_mmap_page *headers[MAX_CPUS];

/*
 * time sorted list of events
 */
struct event {
	struct rb_node rb_node;
	struct list_head list;
	struct data data;      /* this struct varies by command;
				* must contain time and cpu
				*/
};

static struct rb_root events;

static void remove_event(struct event *event)
{
	free(event);
}

static void insert_event(struct event *e_new)
{
	struct rb_root *root = &events;
	struct rb_node **node = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*node != NULL) {
		struct event *e;

		parent = *node;
		e = container_of(parent, struct event, rb_node);
		if (e->data.time > e_new->data.time)
			node = &(*node)->rb_left;
		else if (e->data.time < e_new->data.time)
			node = &(*node)->rb_right;
		else {
			free(e_new);
			time_drops++;
			return;
		}
	}

	rb_link_node(&e_new->rb_node, parent, node);
	rb_insert_color(&e_new->rb_node, root);
}

static void __process_event(struct event *event)
{
	struct event *e, *tmp;

	process_event(&event->data);

	if (event->list.prev == event->list.next)
		return;

	list_for_each_entry_safe(e, tmp, &event->list, list) {
		list_del(&e->list);

		process_event(&e->data);
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

void process_events(void)
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
		if (event->data.time >= end_time)
			break;

		rb_erase(&event->rb_node, rb_root);
		__process_event(event);
		remove_event(event);
	}
}

/*
 * Add event to time sorted backlog queue
 */
static int __handle_bpf_output(void *_data, int size)
{
	struct data *data = _data;
	struct event *event;

	if (numcpus && data->cpu >= numcpus) {
		fprintf(stderr, "CPU in event (%d) is > numcpus (%d)\n",
			data->cpu, numcpus);
		return LIBBPF_PERF_EVENT_ERROR;
	}

	if (size < sizeof(*data)) {
		fprintf(stderr,
			"Event size %d is less than data size %ld\n",
			size, sizeof(*data));
		return LIBBPF_PERF_EVENT_ERROR;
	}

	event = malloc(sizeof(*event));
	if (!event) {
		fprintf(stderr, "Failed to allocate memory for event\n");
		return LIBBPF_PERF_EVENT_ERROR;
	}
	INIT_LIST_HEAD(&event->list);

	memcpy(&event->data, data, sizeof(event->data));
	insert_event(event);
	total_events++;

	return LIBBPF_PERF_EVENT_CONT;
}

static int sys_perf_event_open(struct perf_event_attr *attr,
			       int cpu, unsigned long flags)
{
	pid_t pid = -1;
	int group_fd = -1;

	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int perf_event_mmap_header(int fd, struct perf_event_mmap_page **header)
{
	void *base;
	int mmap_size;

	page_size = getpagesize();
	mmap_size = page_size * (page_cnt + 1);

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
	perf_event_print_fn fn = private_data;
	int ret;

	if (e->header.type == PERF_RECORD_SAMPLE) {
		ret = fn(e->data, e->size);
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

static int perf_event_poller_multi(int *fds,
				   int num_fds, perf_event_print_fn output_fn,
				   void (*round_start_fn)(void),
				   int (*round_complete_fn)(void))
{
	enum bpf_perf_event_ret ret = LIBBPF_PERF_EVENT_DONE;
	struct pollfd *pfds;
	int timeout = 1000;
	void *buf = NULL;
	size_t len = 0;
	int i;

	if (!output_fn)
		output_fn = __handle_bpf_output;

	pfds = calloc(num_fds, sizeof(*pfds));
	if (!pfds)
		return LIBBPF_PERF_EVENT_ERROR;

	for (i = 0; i < num_fds; i++) {
		pfds[i].fd = fds[i];
		pfds[i].events = POLLIN;
	}

	for (;;) {
		poll(pfds, num_fds, timeout);

		if (round_start_fn)
			round_start_fn();

		for (i = 0; i < num_fds; i++) {
			ret = bpf_perf_event_read_simple(headers[i],
							 page_cnt * page_size,
							 page_size, &buf, &len,
							 bpf_perf_event_print,
							 output_fn);
			if (ret != LIBBPF_PERF_EVENT_CONT)
				break;
		}

		if (round_complete_fn && round_complete_fn())
			break;
	}
	free(buf);
	free(pfds);

	return ret;
}

static int output_perf_event_cpu(int map_fd, int cpu, int nevents)
{
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.size = sizeof(attr),
		.wakeup_events = nevents, /* get an fd notification for every event */
	};
	int key = cpu;

	pmu_fds[0] = sys_perf_event_open(&attr, cpu, 0);
	if (pmu_fds[0] < 0) {
		fprintf(stderr, "sys_perf_event_open failed: %d: %s\n",
			errno, strerror(errno));
		return -1;
	}
	if (bpf_map_update_elem(map_fd, &key, &pmu_fds[0], BPF_ANY)) {
		fprintf(stderr, "bpf_map_update_elem failed\n");
		return -1;
	}

	ioctl(pmu_fds[0], PERF_EVENT_IOC_ENABLE, 0);

	return 0;
}

static int output_perf_event(int map_fd, int ncpus, int nevents)
{
	struct perf_event_attr attr = {
		.sample_type = PERF_SAMPLE_RAW,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_BPF_OUTPUT,
		.size = sizeof(attr),
		.wakeup_events = nevents, /* get an fd notification for every event */
	};
	int i;

	for (i = 0; i < ncpus; i++) {
		int key = i;

		pmu_fds[i] = sys_perf_event_open(&attr, i, 0);
		if (pmu_fds[i] < 0) {
			fprintf(stderr, "sys_perf_event_open failed: %d: %s\n",
				errno, strerror(errno));
			return -1;
		}
		if (bpf_map_update_elem(map_fd, &key, &pmu_fds[i], BPF_ANY)) {
			fprintf(stderr, "bpf_map_update_elem failed\n");
			return -1;
		}
		ioctl(pmu_fds[i], PERF_EVENT_IOC_ENABLE, 0);
	}

	return 0;
}

/*
 * obj is expected to have a map named "channel".
 * attach event channel to perf event to get output
 */
int configure_perf_event_channel_cpu(struct bpf_object *obj, int nevents,
				     int cpu)
{
	struct bpf_map *map;
	int map_fd;

	map = bpf_object__find_map_by_name(obj, "channel");
	if (!map) {
		fprintf(stderr, "Failed to get channel map in obj file\n");
		return 1;
	}

	map_fd = bpf_map__fd(map);

	if (output_perf_event_cpu(map_fd, cpu, nevents) ||
	    perf_event_mmap_header(pmu_fds[0], &headers[0]) < 0)
		return 1;

	return 0;
}

int configure_perf_event_channel(struct bpf_object *obj, int nevents)
{
	struct bpf_map *map;
	int map_fd, i;

	numcpus = get_nprocs();
	if (numcpus > MAX_CPUS)
		numcpus = MAX_CPUS;

	map = bpf_object__find_map_by_name(obj, "channel");
	if (!map) {
		fprintf(stderr, "Failed to get channel map in obj file\n");
		return 1;
	}

	map_fd = bpf_map__fd(map);

	if (output_perf_event(map_fd, numcpus, nevents))
		return 1;

	for (i = 0; i < numcpus; i++) {
		if (perf_event_mmap_header(pmu_fds[i], &headers[i]) < 0)
			return 1;
	}

	return 0;
}

void close_perf_event_channel(void)
{
	int i;

	printf("total events: %llu\n", total_events);
	printf("drops due to time collision: %llu\n", time_drops);

	for (i = 0; i < numcpus; i++) {
		ioctl(pmu_fds[i], PERF_EVENT_IOC_DISABLE, 0);
		close(pmu_fds[i]);
	}
}

static int tp_perf_event(int prog_fd, __u64 config)
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

static int tp_event_id(const char *event, bool probe)
{
	char filename[PATH_MAX];
	int fd, n, id = -1;
	char buf[64] = {};

	if (probe)
		snprintf(filename, sizeof(filename), "%s/events/probe/%s/id",
			 tracingfs, event);
	else
		snprintf(filename, sizeof(filename), "%s/events/%s/id",
			 tracingfs, event);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s' to learn id for tracing event '%s'\n",
			filename, event);
		return -1;
	}

	n = read(fd, buf, sizeof(buf)-1);
	if (n < 0) {
		fprintf(stderr, "Failed to open '%s' to learn kprobe type\n",
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

	id = tp_event_id(name, false);
	if (id < 0)
		return 1;

	return tp_perf_event(prog_fd, id);
}

/* tps is a NULL terminated array of tracepoint names.
 * bpf program is expected to be named tracepoint/%s
 */
int do_tracepoint(struct bpf_object *obj, const char *tps[])
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

static int kprobes_event_id(const char *event)
{
	char filename[PATH_MAX];
	int fd, n, id = -1;
	char buf[64] = {};

	snprintf(filename, sizeof(filename), "%s/events/kprobes/%s/id",
		 tracingfs, event);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s' to learn id for tracing event '%s'\n",
			filename, event);
		return -1;
	}

	n = read(fd, buf, sizeof(buf)-1);
	if (n < 0) {
		fprintf(stderr, "Failed to open '%s' to learn kprobe type\n",
			filename);
	} else {
		id = atoi(buf);
	}
	close(fd);

	return id;
}

static int do_kprobe_event(const char *event)
{
	char filename[PATH_MAX];
	int rc = 0;
	int fd;

	snprintf(filename, sizeof(filename), "%s/kprobe_events", tracingfs);

	fd = open(filename, O_WRONLY|O_APPEND);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s' to learn id for event '%s'\n",
			filename, event);
		return -1;
	}
	if (write(fd, event, strlen(event)) != strlen(event)) {
		fprintf(stderr, "Failed writing event '%s' to '%s'\n",
			event, filename);
		rc = -1;
	}
	close(fd);

	return rc;
}

static int kprobe_perf_event_legacy(int prog_fd, const char *func,
				    bool retprobe)
{
	char event[128], pname[64];
	char t = 'p';
	int id;

	if (strlen(func) + 10 > sizeof(pname)) {
		fprintf(stderr,
			"buf size too small in kprobe_perf_event_legacy\n");
		return -1;
	}
	if (retprobe)
		t = 'r';

	/*    probe: p:kprobes/p_<func>_<pid>
	 * retprobe: r:kprobes/r_<func>_<pid>
	 *  delete:  -:kprobes/<p>_<func>_<pid>
	 */
	snprintf(pname, sizeof(pname), "%c_%s_%d", t, func, getpid());
	if (prog_fd < 0)
		snprintf(event, sizeof(event), "-:kprobes/%s", pname);
	else
		snprintf(event, sizeof(event), "%c:kprobes/%s %s", t, pname, func);

	if (do_kprobe_event(event))
		return -1;

	if (prog_fd < 0)
		return 0;

	id = kprobes_event_id(pname);
	if (id < 0) {
		fprintf(stderr, "Failed to get id for '%s'\n", pname);
		return -1;
	}

	return tp_perf_event(prog_fd, id);
}

static int kprobe_event_type(void)
{
	static int kprobe_type = -1;
	static bool checked = false;
	char filename[] = "/sys/bus/event_source/devices/kprobe/type";
	char buf[64] = {};
	int fd, n;

	if (checked)
		return kprobe_type;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;

	n = read(fd, buf, sizeof(buf)-1);
	if (n < 0) {
		fprintf(stderr, "Failed to open '%s' to learn kprobe type\n",
			filename);
	} else {
		kprobe_type = atoi(buf);
	}
	close(fd);

	checked = true;

	return kprobe_type;
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

/* probes is a NULL terminated array of function names to put
 * kprobe. bpf program is expected to be named kprobe/%s.
 * If retprobe is set, bpf program name is expected to be
 * "kprobe/%s_ret"
 */
int kprobe_init(struct bpf_object *obj, struct kprobe_data *probes,
		unsigned int count)
{
	struct bpf_program *prog;
	int prog_fd, attr_type;
	unsigned int i;
	int rc = 0;

	attr_type = kprobe_event_type();

	for (i = 0; i < count; ++i) {
		char buf[256];

		if (probes[i].prog) {
			snprintf(buf, sizeof(buf), "%s", probes[i].prog);
		} else {
			snprintf(buf, sizeof(buf), "kprobe/%s%s",
				 probes[i].func,
				 probes[i].retprobe ? "_ret" : "");
		}

		prog = bpf_object__find_program_by_title(obj, buf);
		if (!prog) {
			printf("Failed to get prog in obj file\n");
			rc = 1;
			continue;
		}
		prog_fd = bpf_program__fd(prog);


		if (attr_type < 0) {
			probes[i].fd = kprobe_perf_event_legacy(prog_fd,
								probes[i].func,
								probes[i].retprobe);
		} else {
			probes[i].fd = kprobe_perf_event(prog_fd,
							 probes[i].func,
							 probes[i].retprobe,
							 attr_type);
		}
		if (probes[i].fd < 0) {
			fprintf(stderr,
				"Failed to create perf_event on %s\n",
				probes[i].func);
			rc = 1;
		}
	}

	return rc;
}

void kprobe_cleanup(struct kprobe_data *probes, unsigned int count)
{
	unsigned int i;
	int attr_type;

	attr_type = kprobe_event_type();
	for (i = 0; i < count; ++i) {
		if (probes[i].fd < 0)
			continue;

		close(probes[i].fd);
		if (attr_type < 0) {
			kprobe_perf_event_legacy(-1, probes[i].func,
						 probes[i].retprobe);
		}
	}
}

static int syscall_event_id(const char *name)
{
	char sysname[PATH_MAX];

	snprintf(sysname, sizeof(sysname), "syscalls/%s", name);

	return tp_event_id(sysname, false);
}

int syscall_perf_event(int prog_fd, const char *name)
{
	int id;

	id = syscall_event_id(name);
	if (id < 0)
		return 1;

	return tp_perf_event(prog_fd, id);
}

void perf_set_page_cnt(int cnt)
{
	page_cnt = cnt;
}

int perf_event_loop(perf_event_print_fn output_fn,
		    void (*start_fn)(void), int (*complete_fn)(void))
{
	return perf_event_poller_multi(pmu_fds, numcpus,
				       output_fn, start_fn, complete_fn);
}

int perf_event_loop_cpu(perf_event_print_fn output_fn,
			 void (*start_fn)(void), int (*complete_fn)(void))
{
	return perf_event_poller_multi(pmu_fds, 1,
                                       output_fn, start_fn, complete_fn);
}
