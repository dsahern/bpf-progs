/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kernel address to symbol interface
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#ifndef _INCLUDE_KSYMS_H_
#define _INCLUDE_KSYMS_H_

#include <linux/rbtree.h>

struct ksym_s {
	struct rb_node rb_node;

	unsigned long addr;
	unsigned long addr_next;
	char name[64];
	char mod[32];
};

int load_ksyms(const char *file);
struct ksym_s *find_ksym(unsigned long addr);
struct ksym_s *new_ksym(unsigned long addr, const char *name, const char *mod);
int insert_ksym(struct ksym_s *new_sym);
void free_ksym(struct ksym_s *sym);
#endif
