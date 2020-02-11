
/* struct data changes between probes, but all definitions are
 * expected to have comm, pid and ppid fields
 */
static __always_inline void set_current_info(struct data *data)
{
	struct task_struct *task, *parent;

	data->pid = bpf_get_current_pid_tgid() >> 32;

	task = (struct task_struct *)bpf_get_current_task();

	if (!bpf_probe_read(&parent, sizeof(parent), &task->real_parent))
		bpf_probe_read(&data->ppid, sizeof(data->ppid), &parent->tgid);

	bpf_get_current_comm(&data->comm, sizeof(data->comm));
}
