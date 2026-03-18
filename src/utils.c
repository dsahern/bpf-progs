#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
