/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_EVENTS_H
#define __PERF_EVENTS_H

#include <linux/perf_event.h>
#include <bpf/libbpf.h>

#define TRACINGFS "/sys/kernel/debug/tracing"

struct perf_event_ctx;

typedef enum bpf_perf_event_ret (*perf_event_fn_t)(struct perf_event_ctx *ctx,
						   void *data, int size);

struct perf_event_ctx {
	perf_event_fn_t fn;
	int *pmu_fds;
	struct perf_event_mmap_page **headers;
	int num_cpus;
	int page_size;
	int page_cnt;  /* pages per mmap */
	__u64 total_events;
	__u64 time_drops;
};

int sys_perf_event_open(struct perf_event_attr *attr,
			int cpu, unsigned long flags);

int perf_event_tp_set_prog(int prog_fd, __u64 config);

int perf_event_syscall(int prog_fd, const char *name);

/* attach channel map to perf */
int perf_event_configure(struct perf_event_ctx *ctx, struct bpf_object *obj,
			 int nevents);

void perf_event_close(struct perf_event_ctx *ctx);

int perf_event_loop(struct perf_event_ctx *ctx,
		    perf_event_fn_t output_fn,
                    void (*round_start_fn)(void),
		    int (*round_complete_fn)(void));

/* if output_fn == NULL default output function is used to
 * queue events to a time sorted event log
 */
int perf_event_loop_cpu(struct perf_event_ctx *ctx,
			perf_event_fn_t output_fn,
			void (*round_start_fn)(void),
			int (*round_complete_fn)(void));
#endif
