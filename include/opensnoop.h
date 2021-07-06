/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _OPENSNOOP_H_
#define _OPENSNOOP_H_

#define MAX_CPUS	128
#define ARGSIZE		128
#define TASK_COMM_LEN	16


enum event_type {
	EVENT_ARG,
	EVENT_RET,
};

struct data {
	__u64 time;
	__u32 tid;
	__u32 pid;
	__u32 ppid;
	__u32 flags;
	__u32 mode;
	__u16 event_type;
	__u16 cpu;
	int retval;
	char comm[TASK_COMM_LEN];
	char filename[ARGSIZE];
};

#endif
