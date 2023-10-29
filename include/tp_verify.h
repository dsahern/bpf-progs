#ifndef _TP_VERIFY_H_
#define _TP_VERIFY_H_

#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

struct tp_ctx {
	char *tp_field;
	unsigned int tp_offset;
	unsigned int tp_size;
	char *struct_field;
	unsigned int struct_offset;
	unsigned int struct_size;
};

#define TP_ARG(name, offset, size, dtype, sname)			\
	{ .tp_field = #name,						\
	  .tp_offset = offset, 						\
	  .tp_size = size,						\
	  .struct_field = #sname,					\
	  .struct_offset = offsetof(struct dtype, sname),		\
	  .struct_size = sizeof_field(struct dtype, sname) }

int tp_validate_context(char *sys_name, char *tp_name,
			struct tp_ctx *ctx, unsigned int ctx_entries);

#endif
