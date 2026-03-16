// SPDX-License-Identifier: GPL-2.0
/* track which processes are doing nested virt
 * David Ahern <dsahern@gmail.com>
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, u64);
	__type(value, u64);
} nested_virt_map SEC(".maps");

static __always_inline void do_nested_kvm(void)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 *entry;

	entry = bpf_map_lookup_elem(&nested_virt_map, &pid);
	if (entry) {
		__sync_fetch_and_add(entry, 1);
	} else {
		u64 val = 1;

		bpf_map_update_elem(&nested_virt_map, &pid, &val, BPF_ANY);
	}
}

SEC("tracepoint/kvm/kvm_nested_vmexit")
int bpf_kvm_nested_exit(void *ctx)
{
	do_nested_kvm();
	return 0;
}

SEC("kprobe/handle_vmresume")
int kp_nested_kvm(void *ctx)
{
	do_nested_kvm();
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int bpf_sched_exit(void *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 *entry;

	entry = bpf_map_lookup_elem(&nested_virt_map, &pid);
	if (entry)
		bpf_map_delete_elem(&nested_virt_map, &pid);

	return 0;
}

char _license[] SEC("license") = "GPL";
