// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <linux/kernel.h>
#include <net/if.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "libbpf_helpers.h"
#include "bpf_util.h"
#include "str_utils.h"

static char bpf_log_buf[256*1024];

static int load_dev_prog(int idx)
{
	struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		BPF_MOV64_IMM(BPF_REG_3, idx),
		BPF_MOV64_IMM(BPF_REG_2,
			      offsetof(struct bpf_sock, bound_dev_if)),
		BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_3,
			    offsetof(struct bpf_sock, bound_dev_if)),
		BPF_MOV64_IMM(BPF_REG_0, 1), /* r0 = verdict */
		BPF_EXIT_INSN(),
	};
	size_t size_insns = ARRAY_SIZE(prog);

	return bpf_load_program(BPF_PROG_TYPE_CGROUP_SOCK, prog, size_insns,
				"GPL", 0, bpf_log_buf, sizeof(bpf_log_buf));
}

static int load_mark_prog(__u32 mark)
{
	struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		BPF_MOV64_IMM(BPF_REG_3, mark),
		BPF_MOV64_IMM(BPF_REG_2, offsetof(struct bpf_sock, mark)),
		BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_3,
			    offsetof(struct bpf_sock, mark)),
		BPF_MOV64_IMM(BPF_REG_0, 1), /* r0 = verdict */
		BPF_EXIT_INSN(),
	};
	size_t size_insns = ARRAY_SIZE(prog);

	return bpf_load_program(BPF_PROG_TYPE_CGROUP_SOCK, prog, size_insns,
				"GPL", 0, bpf_log_buf, sizeof(bpf_log_buf));
}

#ifdef HAVE_BPF_LINK_CREATE
static bool done;

static void sig_handler(int signo)
{
	printf("Terminating by signal %d\n", signo);
	done = true;
}
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] cgroup-path\n"
		"\nOPTS:\n"
		"    -i name       interface to attach device program\n"
		"    -l            use bpf-link\n"
		"    -m mark       load mark program with given mark\n"
		"    -M            set BPF_F_ALLOW_MULTI flag on attach\n"
		"    -O            set BPF_F_ALLOW_OVERRIDE flag on attach\n"
		, prog);
}

static int load_prog(int ifindex, __u32 mark)
{
	int prog_fd;

	if (mark) {
		prog_fd = load_mark_prog(mark);
	} else if (ifindex > 0) {
		prog_fd = load_dev_prog(ifindex);
	} else {
		fprintf(stderr, "Neither mark nor device option set.\n");
		return -1;
	}

	if (prog_fd < 0)
		fprintf(stderr, "Failed to load program\n");

	return prog_fd;
}

static int do_bpf_link(int cg_fd, const char *path, int ifindex, __u32 mark,
		       __u32 flags)
{
#ifdef HAVE_BPF_LINK_CREATE
	int prog_fd, link_fd;

	prog_fd = load_prog(ifindex, mark);
	if (prog_fd < 0)
		return 1;

	link_fd = bpf_link_create(prog_fd, cg_fd,BPF_CGROUP_INET_SOCK_CREATE,
				  NULL);
	if (link_fd < 0) {
		fprintf(stderr, "Failed to attach program to cgroup\n");
		return 1;
	}

	close(cg_fd);
	printf("program attached to %s\n", path);

	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		perror("signal");
		return 1;
	}

	while (!done)
		pause();

	printf("dropping link\n");
	close(link_fd);

	return 0;
#else
	fprintf(stderr, "libbpf does not suppport bpf_link_create\n");
	return 1;
#endif
}

static int do_prog(int cg_fd, const char *path, int ifindex, __u32 mark,
		   __u32 flags)
{
	int prog_fd;

	prog_fd = load_prog(ifindex, mark);
	if (prog_fd < 0)
		return 1;

	if (bpf_prog_attach(prog_fd, cg_fd,
			    BPF_CGROUP_INET_SOCK_CREATE, flags) < 0) {
		fprintf(stderr, "Failed to attach program to cgroup\n");
		return 1;
	}

	close(cg_fd);
	printf("program attached to %s\n", path);

	return 0;
}

int main(int argc, char **argv)
{
	int (*fn)(int cg_fd,  const char *path, int ifindex, __u32 mark,
		  __u32 flags) = do_prog;
	int ifindex = -1, cg_fd, opt;
	__u32 flags = 0, mark = 0;
	unsigned long tmp;

	while ((opt = getopt(argc, argv, ":i:lm:MO")) != -1) {
		switch (opt) {
		case 'i':
			ifindex = if_nametoindex(optarg);
			if (ifindex < 0) {
				fprintf(stderr, "Invalid device\n");
				return 1;
			}
			break;
		case 'l':
			fn = do_bpf_link;
			break;
		case 'm':
			if (str_to_ulong(optarg, &tmp)) {
				fprintf(stderr, "Invalid mark\n");
				return 1;
			}
			mark = (__u32)tmp;
			if ((unsigned long)mark != tmp) {
				fprintf(stderr, "Invalid mark\n");
				return 1;
			}
			break;
		case 'M':
			flags |= BPF_F_ALLOW_MULTI;
			break;
		case 'O':
			flags |= BPF_F_ALLOW_OVERRIDE;
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	cg_fd = open(argv[optind], O_DIRECTORY | O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "Failed to open cgroup path: '%s'\n",
			strerror(errno));
		return -1;
	}

	return fn(cg_fd, argv[optind], ifindex, mark, flags);
}
