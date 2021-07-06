
/* struct data changes between probes, but all definitions are
 * expected to have comm, pid and ppid fields
 */
static __always_inline void set_current_info(struct data *data)
{
	struct task_struct *task, *parent;
	u64 tgid;

	tgid = bpf_get_current_pid_tgid();
	data->pid = (u32)(tgid >> 32);
	data->tid = (u32)tgid;

	task = (struct task_struct *)bpf_get_current_task();

	if (!bpf_probe_read(&parent, sizeof(parent), &task->real_parent))
		bpf_probe_read(&data->ppid, sizeof(data->ppid), &parent->tgid);

	bpf_get_current_comm(&data->comm, sizeof(data->comm));
}
