#pragma once

#include <linux/rbtree.h>

/*
 * rbtree_mgr - generic rbtree manager with pluggable comparators.
 *
 * Callers embed struct rb_node in their own struct and provide two
 * comparator callbacks at init time:
 *
 *   cmp      - node vs node, used during insert
 *   cmp_key  - node vs opaque key, used during find/remove-by-key
 *
 * Both return < 0, 0, or > 0 (same convention as strcmp / memcmp).
 *
 * Example:
 *
 *   struct my_entry {
 *       struct rb_node  node;
 *       int             key;
 *   };
 *
 *   static int cmp_entries(const struct rb_node *a, const struct rb_node *b)
 *   {
 *       const struct my_entry *ea = rb_entry(a, struct my_entry, node);
 *       const struct my_entry *eb = rb_entry(b, struct my_entry, node);
 *       return ea->key - eb->key;
 *   }
 *
 *   static int cmp_entry_key(const struct rb_node *n, const void *key)
 *   {
 *       const struct my_entry *e = rb_entry(n, struct my_entry, node);
 *       return e->key - *(const int *)key;
 *   }
 *
 *   struct rb_tree t;
 *   rb_tree_init(&t, cmp_entries, cmp_entry_key);
 */

typedef int (*rb_cmp_fn)(const struct rb_node *a, const struct rb_node *b);
typedef int (*rb_cmp_key_fn)(const struct rb_node *node, const void *key);

struct rb_tree {
	struct rb_root   root;
	rb_cmp_fn        cmp;      /* node-to-node, for insert */
	rb_cmp_key_fn    cmp_key;  /* node-to-key, for find/remove_key */
};

/*
 * rb_tree_init - initialise a tree with comparator callbacks.
 *
 * @cmp_key may be NULL if find/remove_key will not be used.
 */
void rb_tree_init(struct rb_tree *t, rb_cmp_fn cmp, rb_cmp_key_fn cmp_key);

/*
 * rb_tree_insert - insert a node.
 *
 * Returns 0 on success, -EEXIST if a node that compares equal already exists.
 * On -EEXIST, *existing is set to the colliding node (may be NULL to ignore).
 */
int rb_tree_insert(struct rb_tree *t, struct rb_node *node,
		   struct rb_node **existing);

/*
 * rb_tree_find - look up a node by opaque key.
 *
 * Requires cmp_key to be set.  Returns the matching node or NULL.
 */
struct rb_node *rb_tree_find(const struct rb_tree *t, const void *key);

/*
 * rb_tree_remove - remove a node that is already in the tree.
 */
void rb_tree_remove(struct rb_tree *t, struct rb_node *node);

/*
 * rb_tree_remove_key - find and remove a node by key in one step.
 *
 * Returns the removed node or NULL if not found.
 */
struct rb_node *rb_tree_remove_key(struct rb_tree *t, const void *key);

/*
 * Wrappers around rb_first / rb_last / rb_next / rb_prev for convenience.
 */
static inline struct rb_node *rb_tree_first(const struct rb_tree *t)
{
	return rb_first(&t->root);
}

static inline struct rb_node *rb_tree_last(const struct rb_tree *t)
{
	return rb_last(&t->root);
}

static inline int rb_tree_empty(const struct rb_tree *t)
{
	return RB_EMPTY_ROOT(&t->root);
}

void rb_tree_clean(struct rb_tree *t,
		   void (*clean_fn)(struct rb_node *n, void *priv),
		   void *priv);
