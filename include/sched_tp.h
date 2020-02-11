/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SCHED_TP_H_
#define _SCHED_TP_H_

/* order of arguments from
 * /sys/kernel/tracing/events/sched/sched_switch/format
 * common fields represented by 'unsigned long long unused;'

	field:char prev_comm[16];	offset:8;	size:16;	signed:1;
	field:pid_t prev_pid;	offset:24;	size:4;	signed:1;
	field:int prev_prio;	offset:28;	size:4;	signed:1;
	field:long prev_state;	offset:32;	size:8;	signed:1;
	field:char next_comm[16];	offset:40;	size:16;	signed:1;
	field:pid_t next_pid;	offset:56;	size:4;	signed:1;
	field:int next_prio;	offset:60;	size:4;	signed:1;
 */
struct sched_switch_args {
	unsigned long long unused;

	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
};

/* order of arguments from
 * /sys/kernel/tracing/events/sched/sched_wakeup/format
 * common fields represented by 'unsigned long long unused;'

	field:char comm[16];	offset:8;	size:16;	signed:1;
	field:pid_t pid;	offset:24;	size:4;	signed:1;
	field:int prio;	offset:28;	size:4;	signed:1;
	field:int success;	offset:32;	size:4;	signed:1;
	field:int target_cpu;	offset:36;	size:4;	signed:1;
 */
struct sched_wakeup_args {
	unsigned long long unused;

	char comm[16];
	pid_t pid;
	int prio;
	int success;
	int target_cpu;
};

/* order of arguments from
 * /sys/kernel/tracing/events/sched/sched_process_exit/format
 * common fields represented by 'unsigned long long unused;'

  	field:char comm[16];	offset:8;	size:16;	signed:1;
	field:pid_t pid;	offset:24;	size:4;	signed:1;
	field:int prio;	offset:28;	size:4;	signed:1;
 */
struct sched_exit_args {
	unsigned long long unused;

	char comm[16];
	pid_t pid;
	int prio;
};

/* order of arguments from
 * /sys/kernel/tracing/events/sched/sched_stat_runtime/format
 * common fields represented by 'unsigned long long unused;'

	field:char comm[16];	offset:8;	size:16;	signed:1;
	field:pid_t pid;	offset:24;	size:4;	signed:1;
	field:u64 runtime;	offset:32;	size:8;	signed:0;
	field:u64 vruntime;	offset:40;	size:8;	signed:0;
 */
struct sched_stat_run_args {
	unsigned long long unused;

	char comm[16];
	pid_t pid;
	u64 runtime;
	u64 vruntime;
};

/* order of arguments from
 * /sys/kernel/tracing/events/sched/sched_stat_wait/format
 * common fields represented by 'unsigned long long unused;'

	field:char comm[16];	offset:8;	size:16;	signed:1;
	field:pid_t pid;	offset:24;	size:4;	signed:1;
	field:u64 delay;	offset:32;	size:8;	signed:0;
 */
struct sched_stat_wait_args {
	unsigned long long unused;

	char comm[16];
	pid_t pid;
	u64 delay;
};

#endif
