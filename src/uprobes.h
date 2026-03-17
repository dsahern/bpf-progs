#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

struct uprobe_data {
	const char *prog;
	const char *path;
	const char *func;
	int fd;
	bool retprobe;
};

int uprobe_init(struct bpf_object *obj, struct uprobe_data *probes,
		unsigned int count);

void uprobe_cleanup(struct uprobe_data *probes, unsigned int count);

int uprobe_event_type(void);

int uprobe_perf_event(int prog_fd, const char *path, __u64 offset,
		      int retprobe);
