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
#include "str_utils.h"
#include "libbpf_helpers.h"
#include "perf_events.h"
#include "timestamps.h"

#include "perf_events.c"

static bool done;
static int skip_samples;
static int max_samples, num_samples;

struct socket {
	struct list_head list;

	struct data data;
	int skipped;
	bool first;
};

LIST_HEAD(entries);

static struct socket *get_socket(struct data *data)
{
	struct socket *sk;

	list_for_each_entry(sk, &entries, list) {
		if (!memcmp(&sk->data.s_in6, &data->s_in6, sizeof(data->s_in6)) &&
		    !memcmp(&sk->data.d_in6, &data->d_in6, sizeof(data->d_in6)))
		        return sk;
	}

	sk = calloc(1, sizeof(*sk));
	if (sk) {
		sk->data = *data;
		sk->first = true;
		list_add(&sk->list, &entries);
	}
	return sk;
}

static void print_header(void)
{
	printf("%15s %16s/%4s %16s/%4s %5s\n",
		"TIME", "SOURCE", "PORT", "DEST", "PORT",
		"LEN");

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
	unsigned int sndw, rcvw, snd_next = 0, snd_una = 0;
	unsigned int snd_seq, una_seq;
	struct socket *sk;
	char snd_u, rcv_u;

	if (max_samples)
		num_samples++;

	if (addr_uses_port(&data->s_addr, 22) ||
	    addr_uses_port(&data->d_addr, 22))
		return;

	sk = get_socket(data);
	if (sk && !sk->first) {
		if (sk->data.data_len == data->data_len &&
		    sk->data.snd_cwnd == data->snd_cwnd &&
		    sk->data.snd_wnd == data->snd_wnd &&
		    sk->data.rcv_wnd == data->rcv_wnd)
			goto out;

		sk->skipped++;
		if (sk->skipped < skip_samples)
			goto out;

		sk->skipped = 0;
		snd_next = sk->data.snd_nxt;
		snd_una  = sk->data.snd_una;
	}

	sk->first = false;
	show_timestamps(data->time);

	log_address(&data->s_addr);
	log_address(&data->d_addr);

	if (data->snd_wnd > 1024 * 1024) {
		snd_u = 'M';
		sndw = data->snd_wnd/1024/1024;
	} else if (data->snd_wnd > 1024) {
		snd_u = 'K';
		sndw = data->snd_wnd/1024;
	} else {
		snd_u = 'B';
		sndw = data->snd_wnd/1024;
	}

	if (data->rcv_wnd > 1024 * 1024) {
		rcv_u = 'M';
		rcvw = data->rcv_wnd/1024/1024;
	} else if (data->rcv_wnd > 1024) {
		rcv_u = 'K';
		rcvw = data->rcv_wnd/1024;
	} else {
		rcv_u = 'B';
		rcvw = data->rcv_wnd/1024;
	}

	if (snd_next > data->snd_nxt)
		snd_seq = 0xFFFFFFFF - snd_next + data->snd_nxt;
	else
		snd_seq = data->snd_nxt - snd_next;

	if (snd_una > data->snd_una)
		una_seq = 0xFFFFFFFF - snd_una + data->snd_una;
	else
		una_seq = data->snd_una - snd_una;

	printf(" %5u %8u %8u %8u %u/%u%c/%u%c\n",
		data->data_len, data->mark, snd_seq, una_seq,
		data->snd_cwnd, sndw, snd_u, rcvw, rcv_u);

out:
	sk->data.data_len = data->data_len;
	sk->data.snd_cwnd = data->snd_cwnd;
	sk->data.snd_wnd = data->snd_wnd;
	sk->data.rcv_wnd = data->rcv_wnd;
	sk->data.snd_nxt = data->snd_nxt;
	sk->data.snd_una = data->snd_una;
}

static int tcpprobe_complete(void)
{
	process_events();
	if (max_samples && num_samples >= max_samples)
		done = true;

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
	"	-s N           show data for every Nth sample\n"
	"	-n N           stop after N samples\n"
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

	while ((rc = getopt(argc, argv, "f:s:n:")) != -1)
	{
		switch(rc) {
		case 'f':
			objfile = optarg;
			filename_set = true;
			break;
		case 's':
			if (str_to_int(optarg, 1, 0x7fffffff, &skip_samples)) {
				fprintf(stderr, "Invalid sampling rate\n");
				return 1;
			}
			break;
		case 'n':
			if (str_to_int(optarg, 1, 0x7fffffff, &max_samples)) {
				fprintf(stderr, "Invalid max samples\n");
				return 1;
			}
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
