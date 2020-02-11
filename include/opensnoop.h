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
	u64 time;
	u32 pid;
	u32 ppid;
	u32 flags;
	u32 mode;
	u16 event_type;
	u16 cpu;
	int retval;
	char comm[TASK_COMM_LEN];
	char filename[ARGSIZE];
};

#endif
