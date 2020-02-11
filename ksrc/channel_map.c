
struct bpf_map_def SEC("maps") channel = {
 	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
 	.key_size = sizeof(int),
 	.value_size = sizeof(u32),
 	.max_entries = MAX_CPUS,
};
