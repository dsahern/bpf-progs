/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_EVENTS_H
#define __PERF_EVENTS_H

#include <linux/perf_event.h>
#include <bpf/libbpf.h>

#define TRACINGFS "/sys/kernel/debug/tracing"

struct perf_event_ctx {
	/* called for each event */
	perf_buffer_sample_fn output_fn;

	/* users of cache API */
	__u64 (*event_timestamp)(struct perf_event_ctx *ctx, void *data);
	void (*process_event)(struct perf_event_ctx *ctx, void *data);

	/* called at the end of a polling loop; non-0 terminates polling */
	int (*complete_fn)(struct perf_event_ctx *ctx);

	struct perf_buffer *pb;
	int num_cpus;

	int data_size;
	int page_size;
	int page_cnt;  /* pages per mmap */
	__u64 total_events;
	__u64 time_drops;
	__u64 lost_events;
};

int sys_perf_event_open(struct perf_event_attr *attr,
			int cpu, unsigned long flags);

int perf_event_tp_set_prog(int prog_fd, __u64 config);
int configure_tracepoints(struct bpf_object *obj, const char *bpf_fn[],
			  const char *tps[]);

int perf_event_syscall(int prog_fd, const char *name);

/* attach channel map to perf */
int perf_event_configure(struct perf_event_ctx *ctx, struct bpf_object *obj,
			 const char *map_name);
int configure_raw_tracepoints(struct bpf_object *obj, const char *bpf_fn[],
			      const char *tps[]);

void perf_event_close(struct perf_event_ctx *ctx);

void perf_event_loop(struct perf_event_ctx *ctx);

void perf_event_process_events(struct perf_event_ctx *ctx);

#endif
