// SPDX-License-Identifier: GPL-2.0
/* track which processes are doing nested virt
 * David Ahern <dsahern@gmail.com>
 */

#define KBUILD_MODNAME "kvm_nested"
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") nested_virt_map = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u64),
        .value_size = sizeof(u64),
        .max_entries = 512,
};

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
int tp_nested_kvm(void *ctx)
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
int _version SEC("version") = LINUX_VERSION_CODE;
