// SPDX-License-Identifier: GPL-2.0
/* Resolve addresses to kernel symbols.
 *
 * Copyright (c) 2009-2020 David Ahern <dsahern@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "ksyms.h"
#include "str_utils.h"

static struct rb_root ksyms;
static bool ksyms_initialized;

struct ksym_s *new_ksym(unsigned long addr, const char *name, const char *mod)
{
	struct ksym_s *sym = calloc(1, sizeof(struct ksym_s));

	if(sym) {
		sym->addr = addr;
		sym->name = strdup(name);
		sym->mod = strdup(mod);
	}

	return sym;
}

void free_ksym(struct ksym_s *sym)
{
	free(sym->name);
	free(sym->mod);
	free(sym);
}

static struct ksym_s *__new_ksym(unsigned long addr, char *fields[],
			       int nfields)
{
	return new_ksym(addr, fields[2], nfields > 3 ? fields[3] : "[kernel]");
}

/* 
 * return entry whose addr value is < given argument
 */
struct ksym_s *find_ksym(unsigned long addr)
{
	struct rb_node **p = &ksyms.rb_node;
	struct rb_node *parent = NULL;

	while (*p != NULL) {
		struct ksym_s *sym;

		parent = *p;

		sym = container_of(parent, struct ksym_s, rb_node);
		if (addr >= sym->addr && addr < sym->addr_next)
			return sym;

		if (addr < sym->addr)
			p = &(*p)->rb_left;
		else if (addr > sym->addr)
			p = &(*p)->rb_right;
	}

	return NULL;
}

struct ksym_s *find_ksym_by_name(const char *name)
{
	struct rb_node *node;

	for (node = rb_first(&ksyms); node; node = rb_next(node)) {
		struct ksym_s *sym;

		sym = rb_entry(node, struct ksym_s, rb_node);
		if (!strcmp(sym->name, name))
			return sym;
	}

	return NULL;
}

/* look for sym with this starting address */
static struct ksym_s *find_ksym_start(unsigned long addr)
{
	struct rb_node **p = &ksyms.rb_node;
	struct rb_node *parent = NULL;

	while (*p != NULL) {
		struct ksym_s *sym;

		parent = *p;

		sym = container_of(parent, struct ksym_s, rb_node);
		if (addr == sym->addr)
			return sym;

		if (addr < sym->addr)
			p = &(*p)->rb_left;
		else if (addr > sym->addr)
			p = &(*p)->rb_right;
	}

	return NULL;
}

int insert_ksym(struct ksym_s *new_sym)
{
	struct rb_node **node = &ksyms.rb_node;
	struct rb_node *parent = NULL;

	if (!new_sym->addr_next)
		new_sym->addr_next = new_sym->addr;

#ifdef KSYM_DEBUG
	printf("insert_ksym: %s [%s] %lx -> %lx\n",
		new_sym->name, new_sym->mod, new_sym->addr, new_sym->addr_next);
#endif
	while (*node != NULL) {
		struct ksym_s *sym;

		parent = *node;
		sym = container_of(parent, struct ksym_s, rb_node);
		if (new_sym->addr < sym->addr)
			node = &(*node)->rb_left;
		else if (new_sym->addr > sym->addr)
			node = &(*node)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&new_sym->rb_node, parent, node);
	rb_insert_color(&new_sym->rb_node, &ksyms);

	return 0;
}

static void fixup_ksym(struct ksym_s *sym, char *fields[], int nfields)
{
#ifdef KSYM_DEBUG
	const char *mod = nfields > 3 ? fields[3] : "[kernel]";
	const char *name = fields[2];

	fprintf(stderr, "2 entries with address %lx: %s and %s [%s]\n",
		sym->addr, sym->name, name, mod);
#endif
}

/*
 *  expecting lines with the following format:
 *      addr  symbol  module
 */
int load_ksyms(const char *file)
{
	struct ksym_s *sym = NULL, *prev_sym = NULL;
	unsigned int lineno = 0;
	unsigned long addr = 0;
	char line[1024];
	char *fields[4];
	int nfields;
	int rc = 0;
	char *nl;
	FILE *fp;
	
	if (ksyms_initialized) {
		fprintf(stderr, "ksyms already populated\n");
		return -1;
	}
	
	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr,
			"failed to open %s: %s\n", file, strerror(errno));
		return -1;
	}

	while(fgets(line, sizeof(line), fp))
	{
		const char *stype;

		lineno++;
		nl = strchr(line, '\n');
		if (!nl) {
			fprintf(stderr,
				"failed to read full line at line %u\n", lineno);
			rc = -1;
			break;
		}

		nfields = parsestr(line, " \n\r\t", fields, 4);
		if (nfields < 3) {
			fprintf(stderr, "line %d: not enough fields\n", lineno);
			continue;
		}

		if (str_to_ulong_base(fields[0], &addr, 16) != 0) {
			fprintf(stderr,
				"line %d: failed to convert %s to an integer\n",
				lineno, fields[0]);
			continue;
		}

		sym = NULL;

		/* expect symbol type of 'A' to be at the front of the file */
		stype = fields[1];
		if (*stype == 'A' || *stype == 'a')
			goto next;

		/*
		 * check for multiple entries with the same address
		 */
		if (prev_sym && prev_sym->addr == addr) {
			fixup_ksym(prev_sym, fields, nfields);
			continue;
		}

		sym = find_ksym_start(addr);
		if (sym) {
			fixup_ksym(sym, fields, nfields);
			continue;
		}

		sym = __new_ksym(addr, fields, nfields);
		if (!sym) {
			fprintf(stderr,
				"failed to allocate memory for new ksym entry\n");
			rc = -1;
			break;
		}

next:
		if (prev_sym) {
			prev_sym->addr_next = addr ? : prev_sym->addr;
			rc = insert_ksym(prev_sym);
			if (rc)	{
				fprintf(stderr,
					"failed to insert %s [%s] %lx\n",
					prev_sym->name, prev_sym->mod,
					prev_sym->addr);
				break;
			}
		}
		prev_sym = sym;
	}

	if (prev_sym) {
		prev_sym->addr_next = (unsigned long long)(-1);
		insert_ksym(prev_sym);
	}

	fclose(fp);

	ksyms_initialized = true;

	return rc;
}
