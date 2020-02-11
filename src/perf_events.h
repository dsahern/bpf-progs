/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PERF_EVENTS_H
#define __PERF_EVENTS_H

#include <linux/perf_event.h>
#include <bpf/libbpf.h>

typedef enum bpf_perf_event_ret (*perf_event_print_fn)(void *data, int size);

/* attach channel map to perf */
int configure_perf_event_channel(struct bpf_object *obj, int nevents);
int configure_perf_event_channel_cpu(struct bpf_object *obj, int nevents,
				     int cpu);

void perf_set_page_cnt(int cnt);

int perf_event_loop(perf_event_print_fn output_fn,
                    void (*round_start_fn)(void),
		    int (*round_complete_fn)(void));

/* if output_fn == NULL default output function is used to
 * queue events to a time sorted event log
 */
int perf_event_loop_cpu(perf_event_print_fn output_fn,
			void (*round_start_fn)(void),
			int (*round_complete_fn)(void));
#endif
