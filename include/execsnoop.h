/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _EXECSNOOP_H_
#define _EXECSNOOP_H_

#define MAX_CPUS	128
#define ARGSIZE		128
#define MAXARG		20
#define TASK_COMM_LEN	16

enum event_type {
	EVENT_START,
	EVENT_ARG,
	EVENT_RET,
	EVENT_EXIT,
};

struct data {
	__u64 time;
	__u32 tid;
	__u32 pid;
	__u32 ppid;
	__u16 event_type;
	__u16 cpu;
	int retval;
	char comm[TASK_COMM_LEN];
	char arg[ARGSIZE];
};

#endif
