#pragma once

#include <stdlib.h>
#include "rbtree_mgr.h"

#define TASK_COMM_LEN       16

struct task {
	struct rb_tree threads;
	struct rb_node rb_node;

	char comm[TASK_COMM_LEN];
	__u32 tid;
	__u32 pid;
	__u32 ppid;

	void (*cleanup)(struct task *);

	__u32 priv_size;
	__u8 priv[];
};


void task_init(void);
void task_cleanup(void);

struct task *task_add(const char *comm, __u32 pid, __u32 tid,
		      __u32 ppid, __u32 priv_size,
		      int (*init)(struct task *task, void *priv), void *priv,
		      void (*cleanup)(struct task *));

void task_remove(__u32 pid, __u32 tid);

struct task *task_find(__u32 pid, __u32 tid);

static inline void *task_priv(struct task *task)
{
	return (void *)task->priv;
}


