#ifndef _KPROBES_H_
#define _KPROBES_H_

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

struct kprobe_data {
	const char *prog;
	const char *func;
	int fd;
	bool retprobe;
};

int kprobe_init(struct bpf_object *obj, struct kprobe_data *probes,
		unsigned int count);

void kprobe_cleanup(struct kprobe_data *probes, unsigned int count);

int kprobe_perf_event(int prog_fd, const char *func, int retprobe,
		      int attr_type);

int kprobe_event_type(void);

#endif
