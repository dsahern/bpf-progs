
#pragma once

#include <linux/limits.h>
#include <linux/rbtree.h>

#include "rbtree_mgr.h"

struct maps_entry {
	struct rb_node  node;

	unsigned long   start;
	unsigned long   end;
	char            path[PATH_MAX];
};

void proc_map_init(struct rb_tree *tree);
void proc_map_cleanup(struct rb_tree *tree);

int proc_map_load(struct rb_tree *tree, pid_t pid);
void proc_map_dump(const struct rb_tree *tree);

struct maps_entry *proc_map_lookup(const struct rb_tree *tree, unsigned long addr);

