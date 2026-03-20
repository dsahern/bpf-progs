// SPDX-License-Identifier: GPL-2.0
/*
 * proc_maps - parse /proc/<pid>/maps into an rbtree indexed by start address.
 *
 * Only file-backed mappings are inserted.  Each node records the end address
 * and the backing-file path.  proc_map_lookup returns the entry whose
 * [start, end) range contains the given address.
 *
 * Code initially written by Claude; conversion to library done by me.
 */

#include <linux/rbtree.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proc_maps.h"

/* node-to-node: sort by start address (used during insert) */
static int cmp_entries(const struct rb_node *a, const struct rb_node *b)
{
	const struct maps_entry *ea = rb_entry(a, struct maps_entry, node);
	const struct maps_entry *eb = rb_entry(b, struct maps_entry, node);

	if (ea->start < eb->start)
		return -1;
	if (ea->start > eb->start)
		return 1;
	return 0;
}

/*
 * node-to-key: key is an unsigned long address.
 *
 * Convention (from rbtree_mgr): return > 0 to go left, < 0 to go right.
 *
 *   addr < entry->start  →  key is left of this node  →  return > 0
 *   addr >= entry->end   →  key is right of this node →  return < 0
 *   otherwise            →  addr is within [start, end) → return 0
 */
static int cmp_addr(const struct rb_node *n, const void *key)
{
	const struct maps_entry *e = rb_entry(n, struct maps_entry, node);
	unsigned long addr = *(const unsigned long *)key;

	if (addr < e->start)
		return 1;
	if (addr >= e->end)
		return -1;
	return 0;
}

int proc_map_load(struct rb_tree *tree, pid_t pid)
{
	char path_prev[PATH_MAX];
	char line[PATH_MAX + 256];
	char maps_path[64];
	int count = 0;
	FILE *fp;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);

	fp = fopen(maps_path, "r");
	if (!fp) {
		fprintf(stderr, "cannot open %s: %s\n", maps_path, strerror(errno));
		return -errno;
	}

	path_prev[0] = '\0';

	while (fgets(line, sizeof(line), fp)) {
		char perms[8], path[PATH_MAX], *nl; 
		unsigned int dev_major, dev_minor;
		unsigned long start, end;
		struct maps_entry *e;
		unsigned long offset;
		unsigned long inode;
		int rc;

		nl = strchr(line, '\n');
		if (nl)
			*nl= '\0';

		path[0] = '\0';

		rc = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %4095s",
			    &start, &end, perms, &offset,
			    &dev_major, &dev_minor, &inode, path);

		if (rc < 7)
			continue;

		/* skip pseudo-file mappings like [heap], [stack] */
		if (rc == 8 && path[0] == '[')
			continue;

		/* for entries without a filename, they seem to be related to
		 * the previous object file, so save it and restore here as
		 * needed
		 */
		if (rc == 7)
			strcpy(path, path_prev);
		else if (rc == 8)
			strcpy(path_prev, path);

		e = calloc(1, sizeof(*e));
		if (!e) {
			fclose(fp);
			return -ENOMEM;
		}

		e->start = start;
		e->end   = end;
		snprintf(e->path, sizeof(e->path), "%s", path);

		if (rb_tree_insert(tree, &e->node, NULL) == -EEXIST) {
			/* duplicate start address - keep first mapping */
			free(e);
			continue;
		}

		count++;
	}

	fclose(fp);
	return count;
}

struct maps_entry *proc_map_lookup(const struct rb_tree *tree, unsigned long addr)
{
	struct rb_node *n = rb_tree_find(tree, &addr);

	if (!n)
		return NULL;

	return rb_entry(n, struct maps_entry, node);
}

static void free_entry(struct rb_node *n, void *priv __attribute__((unused)))
{
	free(rb_entry(n, struct maps_entry, node));
}

void proc_map_dump(const struct rb_tree *tree)
{
	struct rb_node *n;

	printf("%-18s %-18s  %s\n", "start", "end", "path");
	printf("%-18s %-18s  %s\n", "-----", "---", "----");

	for (n = rb_first(&tree->root); n; n = rb_next(n)) {
		const struct maps_entry *e = rb_entry(n, struct maps_entry, node);

		printf("0x%016lx  0x%016lx  %s\n", e->start, e->end, e->path);
	}
}

void proc_map_init(struct rb_tree *tree)
{
	rb_tree_init(tree, cmp_entries, cmp_addr);
}

void proc_map_cleanup(struct rb_tree *tree)
{
	rb_tree_clean(tree, free_entry, NULL);
}
