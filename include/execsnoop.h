/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _EXECSNOOP_H_
#define _EXECSNOOP_H_

#define ARGSIZE		128
#define MAXARG		20
#define TASK_COMM_LEN	16

enum event_type {
	EVENT_START,
	EVENT_ARG,
	EVENT_RET,
	EVENT_EXIT,
	EVENT_MAX,
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

/* order of arguments from
 * /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
 * but skipping all of the common fields:

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:const char *const * argv; offset:24;      size:8; signed:0;
        field:const char *const * envp; offset:32;      size:8; signed:0;
 */

struct execve_enter_args {
	unsigned long long unused;

	int __syscall_nr;
	const char * filename;
	const char *const * argv;
	const char *const * envp;
};

/* order of arguments from
 *   /sys/kernel/tracing/events/syscalls/sys_exit_execve/format
 * but skipping all of the common fields:

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;
 */

struct execve_exit_args {
	unsigned long long unused;

	int __syscall_nr;
	long ret;
};

#endif
