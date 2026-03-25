#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

int read_int_from_file(const char *path)
{
	int fd = open(path, O_RDONLY);
	char buf[64];
	ssize_t n;

	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %d: %s\n",
			path, errno, strerror(errno));
		return -1;
	}

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (n <= 0) {
		fprintf(stderr, "Failed to read %s: %d: %s\n",
			path, errno, strerror(errno));
		return -1;
	}

	buf[n] = '\0';

	return atoi(buf);
}

int read_string_from_file(const char *path, char *buf, ssize_t buflen)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;
	char *nl;

	if (fd < 0)
		return -1;

	n = read(fd, buf, buflen - 1);
	close(fd);

	if (n <= 0)
		return -1;

	buf[n] = '\0';

	nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';

	return 0;
}

int write_str_to_file(const char *path, const char *val)
{
	int fd, rc;

	fd = open(path, O_WRONLY|O_APPEND);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %d: %s\n",
			path, errno, strerror(errno));
		return -1;
	}

	if (write(fd, val, strlen(val)) != strlen(val)) {
		fprintf(stderr, "Failed writing '%s' to '%s'\n",
			val, path);
		rc = -1;
	}

	close(fd);

	return rc;
}

/*
 * __cxa_demangle is a C-callable ABI function typically provided by libstdc++.
 */
extern char *__cxa_demangle(const char *mangled_name, char *output_buffer,
			    size_t *length, int *status);

/*
 * Returns a newly allocated string containing only the final function name.
 *
 * Examples:
 *   "_ZN2at6native29vectorized_elementwise_kernel..." -> "vectorized_elementwise_kernel"
 *   demangled "std::vector<int>::push_back(int const&)" -> "push_back"
 *   demangled "foo::bar::baz()" -> "baz"
 *
 * Caller must free() the returned string.
 * Returns NULL on failure.
 */
static char *demangle_function_name(const char *symbol)
{
	const char *name_start, *name_end;
	const char *last_component;
	const char *args_start;
	char *demangled = NULL;
	char *result = NULL;
	const char *scan;
	int angle_depth;
	int status = -1;
	size_t len = 0;

	if (symbol == NULL)
		return NULL;

	demangled = __cxa_demangle(symbol, NULL, NULL, &status);
	if (status != 0 || demangled == NULL)
		return NULL;

	/*
	 * Cut off the argument list first: foo::bar::baz(int) -> foo::bar::baz
	 */
	args_start = strchr(demangled, '(');
	if (args_start == NULL)
		args_start = demangled + strlen(demangled);


	/*
	 * Walk backward from '(' (or end) to find the last "::"
	 * while ignoring template nesting.
	 */
	angle_depth = 0;
	name_start = demangled;
	last_component = demangled;
	for (scan = demangled; scan < args_start; ++scan) {
		if (*scan == '<') {
			angle_depth++;
		} else if (*scan == '>') {
			if (angle_depth > 0)
				angle_depth--;
		} else if (*scan == ':' &&
			   angle_depth == 0 &&
		           (scan + 1) < args_start &&
		           scan[1] == ':') {
			last_component = scan + 2;
		}
	}

	/*
	 * Strip trailing template args from the final component:
	 *   foo<int> -> foo
	 *   operator<< <...> is uncommon here, but this keeps the simple case clean.
	 */
	name_start = last_component;
	name_end = args_start;
	angle_depth = 0;

	for (scan = name_start; scan < args_start; ++scan) {
		if (*scan == '<') {
			if (angle_depth == 0) {
				name_end = scan;
				break;
			}

			angle_depth++;
		} else if (*scan == '>') {
			if (angle_depth > 0)
				angle_depth--;
		}

		len = (size_t)(name_end - name_start);
	}

	if (len == 0) {
		free(demangled);
		return NULL;
	}

	result = (char *)malloc(len + 1);
	if (result == NULL) {
		free(demangled);
		return NULL;
	}

	memcpy(result, name_start, len);
	result[len] = '\0';

	free(demangled);
	return result;
}

/* best effort to convert the returned kernel name to
 * something human readable
 */
void demangle_fn_name(char *sym, int buflen)
{
	char *sym_cpy, *fn_start = NULL, *p, *end, *m;
	char *ns1 = NULL, *ns2 = NULL, *ns3 = NULL;
	long len;

	if (*sym == '\0') {
		snprintf(sym, buflen, "<unknown>");
		return;
	}

	if (sym[0] != '_' || sym[1] != 'Z')
		return;

	m = demangle_function_name(sym);
	if (m) {
		snprintf(sym, buflen, "%s", m);
		free(m);
		return;
	}

	/* might be partial sym; best effort */
	p = sym + 2; /* skip _Z */

	/* possible symspace */
	if (*p == 'N')
		p++;
	if (!isdigit(*p))
		return;

	sym_cpy = strdup(p);
	if (!sym_cpy)
		return;

	p = sym_cpy;
	fn_start = p;
again:
	len = (int)strtol(p, &end, 10);
	if (len == LONG_MAX || len == LONG_MIN || len <= 0)
		goto out_free;

	if (len > strlen(end))
		goto out_free;

	fn_start = end;

	/* stop namespace at first digit */
	*p = '\0';

	p = end + len;
	if (*p != '\0') {
		if (*p == 'I') {
			*p = '\0';
			p++;
			if (*p == 'N')
				p++;
		}
		if (isdigit(*p)) {
			if (!ns1)
				ns1 = end;
			else if (!ns2)
				ns2 = end;
			else if (!ns3)
				ns3 = end;
			goto again;
		}
		p = end + len;
		*p = '\0';
	}

out_free:
	if (ns3)
		snprintf(sym, buflen, "%s::%s::...::%s",
			 ns1, ns2, fn_start);
	else if (ns2)
		snprintf(sym, buflen, "%s::%s::%s",
			 ns1, ns2, fn_start);
	else if (ns1)
		snprintf(sym, buflen, "%s::%s", ns1, fn_start);
	else
		snprintf(sym, buflen, "%s", fn_start);

	free(sym_cpy);
}
