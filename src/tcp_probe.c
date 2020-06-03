// SPDX-License-Identifier: GPL-2.0
/* example using ebpf to monitor tcp connections
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <libgen.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "tcp_probe.h"
#include "libbpf_helpers.h"
#include "perf_events.h"
#include "timestamps.h"

#include "perf_events.c"

static bool done;

static void print_header(void)
{
	printf("%15s %16s/%4s %16s/%4s %5s %8s %8s %8s\n",
		"TIME", "SOURCE", "PORT", "DEST", "PORT",
		"LEN", "MARK", "  SEQ", "  ACK");

	fflush(stdout);
}

static void show_timestamps(__u64 t)
{
	char buf[64];

	printf("%15s", timestamp(buf, sizeof(buf), t));
}

static void log_address(struct sockaddr *sa)
{
	char addrstr[64];

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *) sa;

		printf(" %16s/%4d",
			inet_ntop(AF_INET, &s->sin_addr, addrstr, sizeof(addrstr)),
			ntohs(s->sin_port));
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) sa;

		printf(" %16s/%4d",
			inet_ntop(AF_INET6, &s6->sin6_addr, addrstr, sizeof(addrstr)),
			ntohs(s6->sin6_port));
	}
}

static bool addr_uses_port(struct sockaddr *sa, __u16 port)
{
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *) sa;

		return ntohs(s->sin_port) == port;
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) sa;

		return ntohs(s6->sin6_port) == port;
	}

	return false;
}

static void process_event(struct data *data)
{
	if (addr_uses_port(&data->s_addr, 22) ||
	    addr_uses_port(&data->d_addr, 22))
		return;

	show_timestamps(data->time);

	log_address(&data->s_addr);
	log_address(&data->d_addr);

	printf(" %5u %8u %8u %8u %u/%u/%u\n",
		data->data_len, data->mark, data->snd_nxt, data->snd_una,
		data->snd_cwnd, data->snd_wnd, data->rcv_wnd);
	fflush(stdout);
}

static int tcpprobe_complete(void)
{
	process_events();
	return done;
}

static void sig_handler(int signo)
{
	printf("Terminating by signal %d\n", signo);
	done = true;
}

static void print_usage(char *prog)
{
	printf(
	"usage: %s OPTS\n\n"
	"	-f bpf-file    bpf filename to load\n"
	, basename(prog));
}

int main(int argc, char **argv)
{
	char *objfile = "tcp_probe.o";
	struct bpf_prog_load_attr prog_load_attr = { };
	const char *tps[] = {
		"tcp/tcp_probe",
		NULL
	};
	bool filename_set = false;
	struct bpf_object *obj;
	int nevents = 1000;
	int rc;

	while ((rc = getopt(argc, argv, "f:tTD")) != -1)
	{
		switch(rc) {
		case 'f':
			objfile = optarg;
			filename_set = true;
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (set_reftime())
		return 1;

	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
		return 1;

	if (do_tracepoint(obj, tps))
		return 1;

	if (signal(SIGINT, sig_handler) ||
	    signal(SIGHUP, sig_handler) ||
	    signal(SIGTERM, sig_handler)) {
		perror("signal");
		return 1;
	}

	setlinebuf(stdout);
	setlinebuf(stderr);

	if (configure_perf_event_channel(obj, nevents))
		return 1;

	print_header();

	/* main event loop */
	return perf_event_loop(NULL, NULL, tcpprobe_complete);
}
