#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>

#include "tp_verify.h"
#include "str_utils.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

int tp_validate_context(char *sys_name, char *tp_name,
		        struct tp_ctx *ctx, unsigned int ctx_entries)
{
	unsigned int lineno = 0;
	int n, i = 0, rc = -1;
	char buf[PATH_MAX];
	FILE *fp;

	n = snprintf(buf, sizeof(buf) - 1,
		     "/sys/kernel/debug/tracing/events/%s/%s/format",
		     sys_name, tp_name);
	buf[n] = '\0';

	fp = fopen(buf, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open %s: %s: %d\n",
			buf, strerror(errno), errno);
		return -1;
	}

	while(fgets(buf, sizeof(buf), fp)) {
		unsigned short offs, sz;
		char *fields[10], *b;

		lineno++;

		/* remove '[' to ']' in names such as
		 * "name[sizeof(struct blah)];"
		 */
		b = strchr(buf, '[');
		if (b) {
			while(*b != ';') {
				*b = ' ';
				b++;
			}
		}

		/* only care about lines with field:, offset: and size: */

		n = parsestr(buf, "\n\t :;", fields, ARRAY_SIZE(fields));
		if (n != 9)
			continue;

		if (strcmp(fields[0], "field") ||
		    strcmp(fields[3], "offset") ||
		    strcmp(fields[5], "size"))
			continue;


		if (str_to_ushort(fields[4], &offs) ||
		    str_to_ushort(fields[6], &sz)) {
			fprintf(stderr, "Line %d: Failed to convert offset or size\n",
				lineno);
			goto out;
		}

		/* skipping common lines */
		if (offs < 8)
			continue;

		if (i >= ctx_entries) {
			fprintf(stderr, "Tracepoint %s:%s has new fields after %s\n",
				sys_name, tp_name, fields[2]);
			break;
		}

		if (strcmp(fields[2], ctx[i].tp_field)) {
			fprintf(stderr,
				"Line %d: Unexpected field name: expected \"%s\" have \"%s\"\n",
				lineno, ctx[i].tp_field, fields[2]);
			goto out;
		}

		if (ctx[i].tp_offset != offs) {
			fprintf(stderr,
				"Line %d: Field %s has unexpected offset: expected %d, have %d\n",
				lineno, fields[2], ctx[i].tp_offset, offs);
			goto out;
		}

		if (ctx[i].tp_size != sz) {
			fprintf(stderr,
				"Line %d: Field %s has unexpected size: expected %d, have %d\n",
				lineno, fields[2], ctx[i].tp_size, sz);
			goto out;
		}

		//printf("Match: line %d: field %s -> %s  offset %d -> %d size %d -> %d\n",
		//       lineno, ctx[i].tp_field, fields[2], ctx[i].tp_offset,
		//       offs, ctx[i].tp_size, sz);
		i++;
	}

	if (i == ctx_entries) {
		rc = 0;
		printf("TP matches\n");
	} else
		fprintf(stderr, "Tracepoint %s:%s has chopped fields\n",
			sys_name, tp_name);
out:
	fclose(fp);
	return rc;
}
