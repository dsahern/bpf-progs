// SPDX-License-Identifier: GPL-2.0
/* Analyze dropped packets via an ebpf program on kfree_skb.
 *
 * Copyright (c) 2019-2020 David Ahern <dsahern@gmail.com>
 */
#include <linux/bpf.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <libgen.h>

#include <bpf/bpf.h>

#include "pktdrop.h"
#include "flow.h"
#include "libbpf_helpers.h"
#include "ksyms.h"
#include "perf_events.h"
#include "str_utils.h"
#include "timestamps.h"

#include "perf_events.c"

static u64 display_rate = 10 * NSEC_PER_SEC;
static u64 t_last_display;
static unsigned int drop_thresh = 1;
static unsigned int do_hist;
static const char *hist_sort;
static unsigned int nsid;
static bool done;
static bool debug;

enum {
	HIST_BY_NONE,
	HIST_BY_NETNS,
	HIST_BY_DMAC,
	HIST_BY_SMAC,
	HIST_BY_DIP,
	HIST_BY_SIP,
};

enum {
	HIST_LLDP,
	HIST_ARP,
	HIST_ARP_REQ,
	HIST_ARP_REPLY,
	HIST_ARP_OTHER,
	HIST_IPV4,
	HIST_IPV6,
	HIST_TCP,
	HIST_TCP_SYN,
	HIST_TCP_RST,
	HIST_TCP_FIN,
	HIST_UDP,
	HIST_VRRP,
	HIST_OTHER,
	HIST_MAX,
};

struct drop_hist {
	struct rb_node rb_node;
	union {
		unsigned long	addr;
		u8		dmac[8];  /* 8 > ETH_ALEN */
	};
	char		name[16];
	unsigned int	total_drops;
	u8		aging;
	bool		dead;
	unsigned int	buckets[HIST_MAX];
};

struct drop_loc {
	struct rb_node	rb_node;
	unsigned long	addr;
	char		name[64];
	unsigned int	total_drops;
	u8		aging;
	bool		dead;
};

static struct rb_root all_drop_hists, all_drop_loc;
static unsigned int total_drops;
static unsigned int total_drops_unix;

#define PKT_TYPE_MAX    7   /* used as a mask */
static unsigned int total_drops_by_type[PKT_TYPE_MAX + 1];
static const char *drop_by_type_str[PKT_TYPE_MAX + 1] = {
	[PACKET_HOST]		= "this-host",
	[PACKET_BROADCAST]	= "broadcast",
	[PACKET_MULTICAST]	= "multicast",
	[PACKET_OTHERHOST]	= "other-host",
	[PACKET_OUTGOING]	= "outgoing",
	[PACKET_LOOPBACK]	= "loopback",
	[PACKET_USER]		= "to-user",
	[PACKET_KERNEL]		= "to-kernel",
};

static struct {
	const char *str;
	bool skip;
} hist_desc[] = {
	[HIST_LLDP]      = { .str = "LLDP" },
	[HIST_ARP]       = { .str = "ARP" },
	[HIST_ARP_REQ]   = { .str = "ARP req" },
	[HIST_ARP_REPLY] = { .str = "ARP reply" },
	[HIST_ARP_OTHER] = { .str = "ARP other" },
	[HIST_IPV4]      = { .str = "IPv4" },
	[HIST_IPV6]      = { .str = "IPv6" },
	[HIST_TCP]       = { .str = "TCP" },
	[HIST_TCP_SYN]   = { .str = "TCP syn" },
	[HIST_TCP_RST]   = { .str = "TCP reset" },
	[HIST_TCP_FIN]   = { .str = "TCP fin" },
	[HIST_UDP]       = { .str = "UDP" },
	[HIST_VRRP]      = { .str = "VRRP" },
	[HIST_OTHER]     = { .str = "other" },
};

static struct drop_hist *new_droph(unsigned long addr)
{
	struct drop_hist *droph = calloc(1, sizeof(struct drop_hist));

	if (!droph)
		return NULL;

	droph->addr = addr;

	if (debug)
		printf("new droph: ");
	if (do_hist == HIST_BY_NETNS) {

		if (!addr) {
			strcpy(droph->name, "<unknown>");
		} else {
			struct ksym_s *sym = find_ksym(addr);

			if (sym)
				strncpy(droph->name, sym->name,
					sizeof(droph->name)-1);
			else
				snprintf(droph->name, sizeof(droph->name),
					 "netns-%d", nsid++);
		}
		if (debug)
			printf("%s %lx\n", droph->name, addr);
	} else if (debug) {
		print_mac((u8 *)&addr, true);
		printf("\n");
	}

	return droph;
}

static void remove_droph(struct drop_hist *droph)
{
	struct rb_root *rb_root = &all_drop_hists;

	rb_erase(&droph->rb_node, rb_root);
	free(droph);
}

static int insert_droph(struct drop_hist *new_entry)
{
	struct rb_root *rb_root = &all_drop_hists;
        struct rb_node **node = &rb_root->rb_node;
        struct rb_node *parent = NULL;

	while (*node != NULL) {
		struct drop_hist *entry;

		parent = *node;
		entry = container_of(parent, struct drop_hist, rb_node);
		if (new_entry->addr < entry->addr)
			node = &(*node)->rb_left;
		else if (new_entry->addr > entry->addr)
			node = &(*node)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&new_entry->rb_node, parent, node);
	rb_insert_color(&new_entry->rb_node, rb_root);

	return 0;
}

static struct drop_hist *find_droph(unsigned long addr, bool create)
{
	struct rb_root *rb_root = &all_drop_hists;
	struct rb_node **node = &rb_root->rb_node;
	struct rb_node *parent = NULL;
	struct drop_hist *droph;

	while (*node != NULL) {
		parent = *node;

		droph = container_of(parent, struct drop_hist, rb_node);
		if (addr < droph->addr)
			node = &(*node)->rb_left;
		else if (addr > droph->addr)
			node = &(*node)->rb_right;
		else
			return droph;
	}

	if (!create)
		return NULL;

	droph = new_droph(addr);
	if (droph && insert_droph(droph)) {
		free(droph);
		droph = NULL;
	}

	return droph;
}

static struct drop_loc *new_dropl(void)
{
	return calloc(1, sizeof(struct drop_loc));
}

static void remove_dropl(struct drop_loc *dropl)
{
	struct rb_root *rb_root = &all_drop_loc;

	rb_erase(&dropl->rb_node, rb_root);
	free(dropl);
}

static int insert_dropl(struct drop_loc *new_entry)
{
	struct rb_root *rb_root = &all_drop_loc;
        struct rb_node **node = &rb_root->rb_node;
        struct rb_node *parent = NULL;

	while (*node != NULL) {
		struct drop_loc *entry;

		parent = *node;
		entry = container_of(parent, struct drop_loc, rb_node);
		if (new_entry->addr < entry->addr)
			node = &(*node)->rb_left;
		else if (new_entry->addr > entry->addr)
			node = &(*node)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&new_entry->rb_node, parent, node);
	rb_insert_color(&new_entry->rb_node, rb_root);

	return 0;
}

static struct drop_loc *find_dropl(unsigned long addr, const char *name)
{
	struct rb_root *rb_root = &all_drop_loc;
	struct rb_node **node = &rb_root->rb_node;
	struct rb_node *parent = NULL;
	struct drop_loc *dropl;

	while (*node != NULL) {
		parent = *node;

		dropl = container_of(parent, struct drop_loc, rb_node);
		if (addr < dropl->addr)
			node = &(*node)->rb_left;
		else if (addr > dropl->addr)
			node = &(*node)->rb_right;
		else
			return dropl;
	}

	dropl = new_dropl();
	if (dropl) {
		dropl->addr = addr;
		if (name)
			strncpy(dropl->name, name, sizeof(dropl->name)-1);

		if (insert_dropl(dropl)) {
			free(dropl);
			dropl = NULL;
		}
	}

	return dropl;
}

static void hist_disable_non_ipv4(void)
{
	hist_desc[HIST_LLDP].skip = true;
	hist_desc[HIST_ARP].skip = true;
	hist_desc[HIST_ARP_REQ].skip = true;
	hist_desc[HIST_ARP_REPLY].skip = true;
	hist_desc[HIST_ARP_OTHER].skip = true;
	hist_desc[HIST_IPV6].skip = true;
}

static void show_loc_entries(void)
{
	struct rb_root *rb_root = &all_drop_loc;
	struct drop_loc *dropl;
	struct rb_node *node;

	printf("\n");
	for (node = rb_first(rb_root); node; node = rb_next(node)) {

		dropl = container_of(node, struct drop_loc, rb_node);

		if (dropl->total_drops)
			printf("%32s: %10u\n", dropl->name, dropl->total_drops);

		if (dropl->total_drops)
			dropl->aging = 3;
		else if (--dropl->aging == 0)
			dropl->dead = true;

		dropl->total_drops = 0;
	}

	/* remove dead entries - must be a better way to do this */
restart:
	for (node = rb_first(rb_root); node; node = rb_next(node)) {
		dropl = container_of(node, struct drop_loc , rb_node);
		if (dropl->dead) {
			remove_dropl(dropl);
			goto restart;
		}
	}
}

static void show_hist_entries(void)
{
	struct rb_root *rb_root = &all_drop_hists;
	struct drop_hist *droph;
	struct rb_node *node;
	char buf[64];
	int i;

	for (node = rb_first(rb_root); node; node = rb_next(node)) {
		droph = container_of(node, struct drop_hist, rb_node);

		if (droph->total_drops < drop_thresh)
			goto do_aging;

		printf("  ");
		switch(do_hist) {
		case HIST_BY_NETNS:
			printf("%10s%c", droph->name, droph->dead ? '*' : ' ');
			break;
		case HIST_BY_DMAC:
		case HIST_BY_SMAC:
			print_mac(droph->dmac, true);
			break;
		case HIST_BY_DIP:
		case HIST_BY_SIP:
			inet_ntop(AF_INET, &droph->addr, buf, sizeof(buf));
			printf("%17s ", buf);
			break;
		}

		for (i = 0; i < HIST_MAX; i++) {
			if (!hist_desc[i].skip)
				printf("  %10u", droph->buckets[i]);
			droph->buckets[i] = 0;
		}
		printf("  %10u\n", droph->total_drops);

do_aging:
		if (droph->total_drops)
			droph->aging = 3;
		else if (--droph->aging == 0)
			droph->dead = true;

		droph->total_drops = 0;
	}

	/* remove dead entries - must be a better way to do this */
restart:
	for (node = rb_first(rb_root); node; node = rb_next(node)) {
		droph = container_of(node, struct drop_hist, rb_node);
		if (droph->dead) {
			remove_droph(droph);
			goto restart;
		}
	}
}

static void show_hist(void)
{
	char buf[64];
	int i;

	printf("\n%s: sort by %s,", timestamp(buf, sizeof(buf), 0), hist_sort);
	printf(" total drops: %u (unix sockets %u):\n",
		total_drops, total_drops_unix);
	total_drops = 0;
	total_drops_unix = 0;

	/* name column */
	switch(do_hist) {
	case HIST_BY_DMAC:
	case HIST_BY_SMAC:
	case HIST_BY_DIP:
	case HIST_BY_SIP:
		printf("    %17s", "");
		break;
	default:
		printf("    %10s", "");
	}

	for (i = 0; i < HIST_MAX; i++) {
		if (!hist_desc[i].skip)
			printf("  %10s", hist_desc[i].str);
	}
	printf("  %10s\n", "total");

	show_hist_entries();

	printf("\n  drops by packet type: ");
	for (i = 0; i <= PKT_TYPE_MAX; ++i) {
		printf("  %s: %u", drop_by_type_str[i], total_drops_by_type[i]);
		total_drops_by_type[i] = 0;
	}
	printf("\n");

	show_loc_entries();
}

static void process_tcp(unsigned int *buckets, const struct tcphdr *tcph)
{
	if (tcph->fin)
		buckets[HIST_TCP_FIN]++;
	else if (tcph->rst)
		buckets[HIST_TCP_RST]++;
	else if (tcph->syn)
		buckets[HIST_TCP_SYN]++;
}

static void process_transport(unsigned int *buckets, u8 protocol,
			      const u8 *data, unsigned int len,
			      unsigned int hlen)
{
	switch(protocol) {
	case IPPROTO_TCP:
		buckets[HIST_TCP]++;
		if (len < hlen + sizeof(struct tcphdr))
			return;

		process_tcp(buckets, (struct tcphdr *)(data + hlen));
		break;
	case IPPROTO_UDP:
		buckets[HIST_UDP]++;
		break;
	case IPPROTO_VRRP:
		buckets[HIST_VRRP]++;
		break;
	}
}

static void process_ipv6(unsigned int *buckets, const u8 *data, u32 len)
{
	const struct ipv6hdr *ip6h = (const struct ipv6hdr *)data;

	buckets[HIST_IPV6]++;

	if (len < sizeof(struct ipv6hdr))
		return;

	process_transport(buckets, ip6h->nexthdr, data, len, sizeof(*ip6h));
}

static void process_ipv4(unsigned int *buckets, const u8 *data, u32 len)
{
	const struct iphdr *iph = (const struct iphdr *)data;
	unsigned int hlen;

	buckets[HIST_IPV4]++;

	if (len < sizeof(*iph))
		return;

	if (iph->version != 4)
		return;

	hlen = iph->ihl << 2;
	process_transport(buckets, iph->protocol, data, len, hlen);
}

static void process_arp(unsigned int *buckets, const u8 *data, u32 len)
{
	const struct arphdr *arph = (const struct arphdr *)data;

	buckets[HIST_ARP]++;

	if (len < sizeof(*arph))
		return;

	switch(ntohs(arph->ar_op)) {
	case ARPOP_REQUEST:
		buckets[HIST_ARP_REQ]++;
		break;
	case ARPOP_REPLY:
		buckets[HIST_ARP_REPLY]++;
		break;
	default:
		buckets[HIST_ARP_OTHER]++;
		break;
	}
}

static void process_exit(struct data *data)
{
	struct drop_hist *droph;

	droph = find_droph(data->netns, false);
	if (droph) {
		printf("droph %s/%lx is dead\n", droph->name, droph->addr);
		droph->dead = true;
	}
}

static void process_packet(struct data *data)
{
	u8 pkt_type = data->pkt_type & PKT_TYPE_MAX;
	u8 *pkt_data = data->pkt_data;
	const struct ethhdr *eth = (const struct ethhdr *)pkt_data;
	unsigned int hlen = sizeof(*eth);
	const struct iphdr *iph;
	struct drop_hist *droph;
	unsigned long addr = 0;
	u32 len = data->pkt_len;
	u8 *p = (u8 *)&addr, i;
	struct drop_loc *dropl;
	struct ksym_s *sym;
	u16 proto;

	total_drops++;
	total_drops_by_type[pkt_type]++;

	sym = find_ksym(data->location);

	dropl = find_dropl(data->location, sym ? sym->name : NULL);
	if (dropl)
		dropl->total_drops++;

	if (sym && strstr(sym->name, "unix")) {
		total_drops_unix++;
		return;
	}

	proto = ntohs(eth->h_proto);
	if (proto == ETH_P_8021Q) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *)(pkt_data + hlen);

		hlen += sizeof(*vhdr);
		proto = ntohs(vhdr->h_vlan_encapsulated_proto);
	}

	pkt_data += hlen;
	len -= hlen;

	switch(do_hist) {
	case HIST_BY_NETNS:
		addr = data->netns;
		break;
	case HIST_BY_DMAC:
		for (i = 0; i < 6; ++i)
			p[i] = eth->h_dest[5-i];
		break;
	case HIST_BY_SMAC:
		for (i = 0; i < 6; ++i)
			p[i] = eth->h_source[5-i];
		break;
	case HIST_BY_DIP:
	case HIST_BY_SIP:
		if (proto != ETH_P_IP)
			return;
		if (len < sizeof(*iph))
			return;
		iph = (const struct iphdr *)pkt_data;
		if (do_hist == HIST_BY_DIP)
			memcpy(&addr, &iph->daddr, 4);
		else
			memcpy(&addr, &iph->saddr, 4);
		break;
	default:
		return;
	}

	droph = find_droph(addr, true);
	if (!droph) {
		fprintf(stderr, "failed to allocate droph for addr %lx\n",
			addr);
		return;
	}

	droph->total_drops++;

	switch(proto) {
	case ETH_P_ARP:
		process_arp(droph->buckets, pkt_data, len);
		break;
        case ETH_P_IP:
		process_ipv4(droph->buckets, pkt_data, len);
		break;
        case ETH_P_IPV6:
		process_ipv6(droph->buckets, pkt_data, len);
		break;
        case ETH_P_LLDP:
		droph->buckets[HIST_LLDP]++;
		break;
	default:
		droph->buckets[HIST_OTHER]++;
		break;
	}
}

static struct ksym_s *find_ksym_droph(unsigned long addr)
{
	struct ksym_s *sym;

	if (!addr)
		return NULL;

	sym = find_ksym(addr);
	if (!sym) {
		char buf[16];

		snprintf(buf, sizeof(buf), "droph-%d", ++nsid);
		sym = new_ksym(addr, buf, "[kernel]");
		if (insert_ksym(sym)) {
			free_ksym(sym);
			sym = NULL;
		}
	}

	return sym;
}

static void show_packet(struct data *data)
{
	u8 pkt_type = data->pkt_type & PKT_TYPE_MAX;
	struct ksym_s *sym;
	bool is_unix;
	char buf[64];
	u32 len;

	printf("%15s  %3u  ",
	       timestamp(buf, sizeof(buf), data->time), data->ifindex);

	printf("%12s  ", drop_by_type_str[pkt_type]);

	sym = find_ksym_droph(data->netns);
	if (sym)
		printf("%10s", sym->name);
	else
		printf("%lx", data->netns);

	printf("  %3u  %3u  %3u  ",
		data->pkt_len, data->nr_frags, data->gso_size);

	sym = find_ksym(data->location);
	if (sym) {
		u64 offset = data->location - sym->addr;

		printf("%s+0x%lx (%lx)\n",
		       sym->name, offset, data->location);

		is_unix = strstr(sym->name, "unix") != NULL;
	} else {
		printf("%lx\n", data->location);
		is_unix = false;
	}

	len = data->pkt_len;
	if (len > sizeof(data->pkt_data))
		len = sizeof(data->pkt_data);

	if (data->protocol || !is_unix) {
		struct flow fl = {};

		if (data->vlan_tci) {
			fl.has_vlan = true;
			fl.vlan.outer_vlan_TCI = data->vlan_tci;
		}
		if (parse_pkt(&fl, data->protocol, data->pkt_data, len))
			printf("*** failed to parse ***\n");
		else
			print_flow(&fl);
	}
	printf("\n");
}

static void process_event(struct data *data)
{
	switch (data->event_type) {
	case EVENT_SAMPLE:
		if (do_hist)
			process_packet(data);
		else
			show_packet(data);
		break;
	case EVENT_EXIT:
		process_exit(data);
		break;
	}
}

static int pktdrop_complete(void)
{
	process_events();

	if (do_hist) {
		u64 t_mono = get_time_ns(CLOCK_MONOTONIC);

		if (t_mono > t_last_display + display_rate) {
			t_last_display = t_mono;
			show_hist();
		}
	}
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
	"	-k kallsyms    load kernel symbols from this file\n"
	"	-s <type>      show summary by type (netns, dmac, smac, dip, sip)\n"
	"	-r rate        display rate (seconds) to dump summary\n"
	"	-t num         only display entries with drops more than num\n"
	"	-i             ignore kprobe error (4.14 can not install kprobe on fib_net_exit)\n"
	"	-m count       set number of pages in perf buffers\n"
	, basename(prog));
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = { };
	const char *kallsyms = "/proc/kallsyms";
	bool skip_kprobe_err = false;
	char *objfile = "pktdrop.o";
	bool filename_set = false;
	const char *probes[] = {
		"fib_net_exit",
		NULL,
	};
	const char *tps[] = {
		"skb/kfree_skb",
		NULL,
	};
	struct bpf_object *obj;
	int nevents = 1000;
	int pg_cnt = 0;
	int rc, r;

	while ((rc = getopt(argc, argv, "f:ik:r:s:t:m:")) != -1)
	{
		switch(rc) {
		case 'f':
			objfile = optarg;
			filename_set = true;
			break;
		case 'i':
			skip_kprobe_err = true;
			break;
		case 'k':
			kallsyms = optarg;
			break;
		case 'r':
			r = atoi(optarg);
			if (!r) {
				fprintf(stderr, "Invalid display rate\n");
				return 1;
			}
			display_rate = r * NSEC_PER_SEC;
			break;
		case 's':
			if (strcmp(optarg, "netns") == 0) {
				hist_sort = "network namespace";
				do_hist = HIST_BY_NETNS;
			} else if (strcmp(optarg, "dmac") == 0) {
				hist_sort = "destination mac";
				do_hist = HIST_BY_DMAC;
			} else if (strcmp(optarg, "smac") == 0) {
				hist_sort = "source mac";
				do_hist = HIST_BY_SMAC;
			} else if (strcmp(optarg, "dip") == 0) {
				hist_sort = "destination ip";
				do_hist = HIST_BY_DIP;
			} else if (strcmp(optarg, "sip") == 0) {
				hist_sort = "source ip";
				do_hist = HIST_BY_SIP;
			} else {
				fprintf(stderr, "Invalid sort option\n");
				return 1;
			}
			break;
		case 't':
			r = atoi(optarg);
			if (!r) {
				fprintf(stderr, "Invalid drop threshold\n");
				return 1;
			}
			drop_thresh = r;
			break;
		case 'm':
			if (str_to_int(optarg, 64, 32768, &pg_cnt)) {
				fprintf(stderr, "Invalid page count\n");
				return 1;
			}
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (pg_cnt)
		perf_set_page_cnt(pg_cnt);

	if (set_reftime())
		return 1;

	if (load_ksyms(kallsyms))
		return 1;

	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
		return 1;

	if (do_tracepoint(obj, tps))
		return 1;

	switch(do_hist) {
	case HIST_BY_NETNS:
		if (do_kprobe(obj, probes, 0) && !skip_kprobe_err)
			return 1;
		break;
	case HIST_BY_DIP:
	case HIST_BY_SIP:
		hist_disable_non_ipv4();
		break;
	}

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

	if (do_hist)
		t_last_display = get_time_ns(CLOCK_MONOTONIC);

	/* main event loop */
	return perf_event_loop(NULL, NULL, pktdrop_complete);
}
