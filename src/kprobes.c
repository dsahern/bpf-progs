// SPDX-License-Identifier: GPL-2.0
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "kprobes.h"
#include "perf_events.h"

static int kprobes_event_id(const char *event)
{
	char filename[PATH_MAX];
	int fd, n, id = -1;
	char buf[64] = {};

	/* "probes" directory for some use cases? */
	snprintf(filename, sizeof(filename), "%s/events/kprobes/%s/id",
		 TRACINGFS, event);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s' to learn id for tracing event '%s'\n",
			filename, event);
		return -1;
	}

	n = read(fd, buf, sizeof(buf)-1);
	if (n < 0) {
		fprintf(stderr, "Failed to open '%s' to learn kprobe type\n",
			filename);
	} else {
		id = atoi(buf);
	}
	close(fd);

	return id;
}

static int do_kprobe_event(const char *event)
{
	char filename[PATH_MAX];
	int rc = 0;
	int fd;

	snprintf(filename, sizeof(filename), "%s/kprobe_events", TRACINGFS);

	fd = open(filename, O_WRONLY|O_APPEND);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s' to learn id for event '%s'\n",
			filename, event);
		return -1;
	}
	if (write(fd, event, strlen(event)) != strlen(event)) {
		fprintf(stderr, "Failed writing event '%s' to '%s'\n",
			event, filename);
		rc = -1;
	}
	close(fd);

	return rc;
}

static int kprobe_perf_event_legacy(int prog_fd, const char *func,
				    bool retprobe)
{
	char event[128], pname[64];
	char t = 'p';
	int id;

	if (strlen(func) + 10 > sizeof(pname)) {
		fprintf(stderr,
			"buf size too small in kprobe_perf_event_legacy\n");
		return -1;
	}
	if (retprobe)
		t = 'r';

	/*    probe: p:kprobes/p_<func>_<pid>
	 * retprobe: r:kprobes/r_<func>_<pid>
	 *  delete:  -:kprobes/<p>_<func>_<pid>
	 */
	snprintf(pname, sizeof(pname), "%c_%s_%d", t, func, getpid());
	if (prog_fd < 0)
		snprintf(event, sizeof(event), "-:kprobes/%s", pname);
	else
		snprintf(event, sizeof(event), "%c:kprobes/%s %s", t, pname, func);

	if (do_kprobe_event(event))
		return -1;

	if (prog_fd < 0)
		return 0;

	id = kprobes_event_id(pname);
	if (id < 0) {
		fprintf(stderr, "Failed to get id for '%s'\n", pname);
		return -1;
	}

	return perf_event_tp_set_prog(prog_fd, id);
}

static int kprobe_event_type(void)
{
	char filename[] = "/sys/bus/event_source/devices/kprobe/type";
	static int kprobe_type = -1;
	static bool checked = false;
	char buf[64] = {};
	int fd, n;

	if (checked)
		return kprobe_type;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -1;

	n = read(fd, buf, sizeof(buf)-1);
	if (n < 0) {
		fprintf(stderr, "Failed to open '%s' to learn kprobe type\n",
			filename);
	} else {
		kprobe_type = atoi(buf);
	}
	close(fd);

	checked = true;

	return kprobe_type;
}

/* probes is a NULL terminated array of function names to put
 * kprobe. bpf program is expected to be named kprobe/%s.
 * If retprobe is set, bpf program name is expected to be
 * "kprobe/%s_ret"
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

		if (probes[i].prog) {
			snprintf(buf, sizeof(buf), "%s", probes[i].prog);
		} else {
			snprintf(buf, sizeof(buf), "kprobe/%s%s",
				 probes[i].func,
				 probes[i].retprobe ? "_ret" : "");
		}

		prog = bpf_object__find_program_by_title(obj, buf);
		if (!prog) {
			printf("Failed to get prog in obj file\n");
			rc = 1;
			continue;
		}
		prog_fd = bpf_program__fd(prog);


		if (attr_type < 0) {
			probes[i].fd = kprobe_perf_event_legacy(prog_fd,
								probes[i].func,
								probes[i].retprobe);
		} else {
			probes[i].fd = kprobe_perf_event(prog_fd,
							 probes[i].func,
							 probes[i].retprobe,
							 attr_type);
		}
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
	int attr_type;

	attr_type = kprobe_event_type();
	for (i = 0; i < count; ++i) {
		if (probes[i].fd < 0)
			continue;

		close(probes[i].fd);
		if (attr_type < 0) {
			kprobe_perf_event_legacy(-1, probes[i].func,
						 probes[i].retprobe);
		}
	}
}
