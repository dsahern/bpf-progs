/* started by claude as a wrapper to linux's rbtree implementation.
 * enhancements as needed.
 */
#include <errno.h>
#include <linux/rbtree.h>
#include "rbtree_mgr.h"

void rb_tree_init(struct rb_tree *t, rb_cmp_fn cmp, rb_cmp_key_fn cmp_key)
{
	t->root    = RB_ROOT;
	t->cmp     = cmp;
	t->cmp_key = cmp_key;
}

int rb_tree_insert(struct rb_tree *t, struct rb_node *node,
		   struct rb_node **existing)
{
	struct rb_node **link = &t->root.rb_node;
	struct rb_node  *parent = NULL;
	int rc;

	if (existing)
		*existing = NULL;

	while (*link) {
		parent = *link;
		rc = t->cmp(node, parent);
		if (rc < 0)
			link = &parent->rb_left;
		else if (rc > 0)
			link = &parent->rb_right;
		else {
			if (existing)
				*existing = parent;
			return -EEXIST;
		}
	}

	rb_link_node(node, parent, link);
	rb_insert_color(node, &t->root);
	return 0;
}

struct rb_node *rb_tree_find(const struct rb_tree *t, const void *key)
{
	struct rb_node *n = t->root.rb_node;

	while (n) {
		int rc = t->cmp_key(n, key);

		if (rc > 0)
			n = n->rb_left;
		else if (rc < 0)
			n = n->rb_right;
		else
			return n;
	}

	return NULL;
}

void rb_tree_remove(struct rb_tree *t, struct rb_node *node)
{
	rb_erase(node, &t->root);
	RB_CLEAR_NODE(node);
}

struct rb_node *rb_tree_remove_key(struct rb_tree *t, const void *key)
{
	struct rb_node *node = rb_tree_find(t, key);

	if (node)
		rb_tree_remove(t, node);

	return node;
}

void rb_tree_clean(struct rb_tree *t,
		   void (*clean_fn)(struct rb_node *n, void *priv),
		   void *priv)
{
	struct rb_root *rb_root = &t->root;

	while (1) {
		struct rb_node *node;

		node = rb_first(rb_root);
		if (!node)
			break;

		/* remove from rbtree, but does not free memory */
		rb_tree_remove(t, node);

		if (clean_fn)
			clean_fn(node, priv);
	}
}
