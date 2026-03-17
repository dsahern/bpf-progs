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
