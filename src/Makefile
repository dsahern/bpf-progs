# SPDX-License-Identifier: GPL-2.0

include ../config.mk

ifneq (,$(BUILDDIR))
OBJDIR = $(BUILDDIR)/src/obj/
else
OBJDIR = obj/
endif

ifneq (,$(BUILDDIR))
BINDIR = $(BUILDDIR)/src/bin/
else
BINDIR = bin/
endif

MODS += $(BINDIR)tcp_probe
MODS += $(BINDIR)xdp_l2fwd
MODS += $(BINDIR)xdp_l3fwd
MODS += $(BINDIR)xdp_acl

MODS += $(BINDIR)execsnoop
MODS += $(BINDIR)opensnoop
MODS += $(BINDIR)cgroup_sock
MODS += $(BINDIR)kvm-nested

MODS += $(BINDIR)netmon
MODS += $(BINDIR)pktlatency
MODS += $(BINDIR)ovslatency
MODS += $(BINDIR)net_rx_action
MODS += $(BINDIR)napi_poll
MODS += $(BINDIR)xdp_devmap_xmit

MODS += $(BINDIR)xdp_dummy
MODS += $(BINDIR)vm_info

VPATH := .

CC = gcc
CFLAGS += -O2 -g -Wall

INCLUDES  = -I../include -I../include/uapi
INCLUDES += -I../include/tools

ifneq (,$(LIBBPF_DIR))
BPF_LINK_FEAT := $(shell egrep 'bpf_link_create' $(LIBBPF_DIR)/usr/include/bpf/libbpf.h)
ifneq (,$(BPF_LINK_FEAT))
CFLAGS += -DHAVE_BPF_LINK_CREATE
endif
else
LIBBPF=-lbpf
endif

COMMON += $(OBJDIR)perf_events.o
COMMON += $(OBJDIR)kprobes.o
COMMON += $(OBJDIR)timestamps.o
COMMON += $(OBJDIR)libbpf_helpers.o
COMMON += $(OBJDIR)str_utils.o
COMMON += $(OBJDIR)rbtree.o
COMMON += $(OBJDIR)parse_pkt.o
COMMON += $(OBJDIR)print_pkt.o
COMMON += $(OBJDIR)ksyms.o
COMMON += $(OBJDIR)tp_verify.o

all: build $(MODS)

build:
	@mkdir -p $(OBJDIR) $(BINDIR)

$(BINDIR)%: $(OBJDIR)%.o $(COMMON)
	$(QUIET_LINK)$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(BINDIR)xdp_%: $(OBJDIR)xdp_%_user.o $(COMMON)
	$(QUIET_LINK)$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(OBJDIR)%.o: %.c
	$(QUIET_CC)$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) -c $^ -o $@

$(BINDIR)netmon: $(OBJDIR)netmon.o $(COMMON)
	$(QUIET_LINK)$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) $^ -o $@ $(LDLIBS) -lpcap

clean:
	@rm -rf $(OBJDIR) $(BINDIR)
