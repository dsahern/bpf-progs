// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "kprobes.h"
#include "utils.h"
#include "perf_events.h"

int kprobe_event_type(void)
{
	static int kprobe_type = -1;
	static bool checked = false;

	if (checked)
		return kprobe_type;

	kprobe_type = read_int_from_file("/sys/bus/event_source/devices/kprobe/type");
	if (kprobe_type != -1)
		checked = true;

	return kprobe_type;
}

/* probes is a NULL terminated array of function names to put
 * kprobe.
 */
int kprobe_init(struct bpf_object *obj, struct kprobe_data *probes,
		unsigned int count)
{
	struct bpf_program *prog;
	int prog_fd, attr_type;
	unsigned int i;
	int rc = 0;

	attr_type = kprobe_event_type();

	for (i = 0; i < count; ++i) {
		char buf[256];

		snprintf(buf, sizeof(buf), "%s", probes[i].prog);

		prog = bpf_object__find_program_by_name(obj, buf);
		if (!prog) {
			fprintf(stderr,
				"%s: Failed to get prog \"%s\" in obj file\n",
				__func__, buf);
			rc = 1;
			continue;
		}
		prog_fd = bpf_program__fd(prog);


		probes[i].fd = kprobe_perf_event(prog_fd,
						 probes[i].func,
						 probes[i].retprobe,
						 attr_type);

		if (probes[i].fd < 0) {
			fprintf(stderr,
				"Failed to create perf_event on %s\n",
				probes[i].func);
			rc = 1;
		}
	}

	return rc;
}

void kprobe_cleanup(struct kprobe_data *probes, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; ++i) {
		if (probes[i].fd < 0)
			continue;

		close(probes[i].fd);
	}
}
