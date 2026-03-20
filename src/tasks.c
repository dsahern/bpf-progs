// SPDX-License-Identifier: GPL-2.0
/* Track tasks by pid and then threads under it.
 *
 * Copyright (c) 2019-2026 David Ahern <dsahern@gmail.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "tasks.h"
#include "utils.h"

static struct rb_tree all_tasks;

static int task_tid_cmp(const struct rb_node *a, const struct rb_node *b)
{
	struct task *t_a, *t_b;

	t_a = container_of(a, struct task, rb_node);
	t_b = container_of(b, struct task, rb_node);

	return (__s32)t_a->tid - (__s32)t_b->tid;
}

static int task_tid_cmp_key(const struct rb_node *node, const void *key)
{
	struct task *t;
	__u32 tid = (__u32)((__u64)key);

	t = container_of(node, struct task, rb_node);

	return (__s32)t->tid - tid;
}

static void task_free(struct task *task, void *priv);

static void task_free_node(struct rb_node *node, void *priv)
{
	struct task *task = container_of(node, struct task, rb_node);

	task_free(task, priv);
}

static void task_free(struct task *task, void *priv)
{
	if (task->pid == task->tid)
		rb_tree_clean(&task->threads, task_free_node, NULL);

	if (task->cleanup)
		task->cleanup(task);

	free(task);
}

static struct task *task_alloc(const char *comm, __u32 pid, __u32 tid,
			       __u32 ppid, __u32 priv_size,
			       void (*cleanup)(struct task *))
{
	struct task *task;

	task = calloc(1, sizeof(*task) + priv_size);
	if (!task) {
		fprintf(stderr, "calloc failed for new task\n");
		return NULL;
	}

	task->tid = tid;
	task->pid = pid;
	task->ppid = ppid;
	task->priv_size = priv_size;
	task->cleanup = cleanup;

	if (comm && *comm != '\0') {
		snprintf(task->comm, sizeof(task->comm), "%s", comm);
	} else {
		char path[64];

		snprintf(path, sizeof(path), "/proc/%d/task/%d/comm", pid, tid);
		if (read_string_from_file(path, task->comm, sizeof(task->comm)))
			strcpy(task->comm, "<unknown>");
	}

	//proc_map_init(&task->proc_maps);
	//proc_map_load(&task->proc_maps, task->pid);

	rb_tree_init(&task->threads, task_tid_cmp, task_tid_cmp_key);

	return task;
}

struct task *task_add(const char *comm, __u32 pid, __u32 tid,
		      __u32 ppid, __u32 priv_size,
		      int (*init_fn)(struct task *, void *priv), void *priv,
		      void (*cleanup_fn)(struct task *))
{
	struct task *task, *thread;
	struct rb_node *node;

	/* find main thread */
	node = rb_tree_find(&all_tasks, (void *)((__u64)pid));
	if (!node) {
		task = task_alloc(pid == tid ? comm : NULL,
				  pid, pid, ppid, priv_size, cleanup_fn);
		if (!task)
			return NULL;

		if (init_fn && init_fn(task, priv)) {
			task_free(task, NULL);
			return NULL;
		}

		if (rb_tree_insert(&all_tasks, &task->rb_node, NULL)) {
			fprintf(stderr, "rb_tree_insert failed for task %s %u/%u\n",
				task->comm, task->pid, task->tid);
			task_free(task, NULL);
			return NULL;
		}
	} else {
		task = container_of(node, struct task, rb_node);
	}

	if (task->tid == tid)
		return task;

	node = rb_tree_find(&task->threads, (void *)((__u64)tid));
	if (!node) {
		thread = task_alloc(comm, pid, tid, ppid, priv_size, cleanup_fn);
		if (!thread)
			return NULL;

		if (init_fn && init_fn(thread, priv)) {
			task_free(thread, NULL);
			return NULL;
		}

		if (rb_tree_insert(&task->threads, &thread->rb_node, NULL)) {
			fprintf(stderr, "rb_tree_insert failed for task %s %u/%u\n",
				thread->comm, thread->pid, thread->tid);
			task_free(thread, NULL);
			return NULL;
		}
	} else {
		thread = container_of(node, struct task, rb_node);
	}

	return thread;
}

struct task *task_find(__u32 pid, __u32 tid)
{
	struct rb_node *node;
	struct task *task;

	node = rb_tree_find(&all_tasks, (void *)((__u64)pid));
	if (!node)
		return NULL;

	task = container_of(node, struct task, rb_node);
	if (pid == tid)
		return task;

	node = rb_tree_find(&task->threads, (void *)((__u64)tid));
	return node ? container_of(node, struct task, rb_node) : NULL;
}

void task_remove(__u32 pid, __u32 tid)
{
	struct task *task;
	struct rb_node *node;

	node = rb_tree_find(&all_tasks, (void *)((__u64)pid));
	if (!node)
		return;

	task = container_of(node, struct task, rb_node);
	if (tid == pid) {
		rb_tree_remove(&all_tasks, node);
	} else {
		node = rb_tree_find(&task->threads, (void *)((__u64)tid));
		if (!node)
			return;

		rb_tree_remove(&task->threads, node);

		/* overwrite parent task with thread */
		task = container_of(node, struct task, rb_node);
	}

	task_free(task, NULL);
}

static int task_pid_cmp(const struct rb_node *a, const struct rb_node *b)
{
	struct task *t_a, *t_b;

	t_a = container_of(a, struct task, rb_node);
	t_b = container_of(b, struct task, rb_node);

	return (__s32)t_a->pid - (__s32)t_b->pid;
}

static int task_pid_cmp_key(const struct rb_node *node, const void *key)
{
	struct task *t;
	__s32 pid = (__s32)((__u64)key);

	t = container_of(node, struct task, rb_node);

	return (__s32)t->pid - pid;
}

void task_init(void)
{
	rb_tree_init(&all_tasks, task_pid_cmp, task_pid_cmp_key);
}

void task_cleanup(void)
{
	rb_tree_clean(&all_tasks, task_free_node, NULL);
}
