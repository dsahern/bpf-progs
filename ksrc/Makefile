# SPDX-License-Identifier: GPL-2.0

include ../config.mk

ifneq (,$(BUILDDIR))
OBJDIR = $(BUILDDIR)/ksrc/obj/
else
OBJDIR = obj/
endif

MODS += $(OBJDIR)execsnoop.o
MODS += $(OBJDIR)opensnoop.o
MODS += $(OBJDIR)kvm-nested.o

MODS += $(OBJDIR)pktdrop.o
MODS += $(OBJDIR)pktlatency.o
MODS += $(OBJDIR)ovslatency.o
MODS += $(OBJDIR)net_rx_action.o
MODS += $(OBJDIR)napi_poll.o
MODS += $(OBJDIR)xdp_devmap_xmit.o

MODS += $(OBJDIR)tcp_probe.o
MODS += $(OBJDIR)xdp_l2fwd.o
MODS += $(OBJDIR)xdp_l3fwd.o
MODS += $(OBJDIR)xdp_dummy.o
MODS += $(OBJDIR)xdp_vmegress.o

MODS += $(OBJDIR)acl_vm_tx.o
MODS += $(OBJDIR)acl_vm_rx.o
MODS += $(OBJDIR)rx_acl.o

VPATH := .

# rule is based on samples/bpf/Makefile
DEFS = -D__TARGET_ARCH_x86 $(EXTRA_DEFS)

CFLAGS += -O2 -g $(EXTRA_CFLAGS)

INCLUDES  = -I../include

all: build $(MODS)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

build:
	@mkdir -p $(OBJDIR)

$(OBJDIR)%.o: %.c vmlinux.h
	$(QUIET_CLANG)$(CLANG) $(INCLUDES) $(DEFS) $(CFLAGS) \
		-O2 -target bpf -c $< -o $@

clean:
	@rm -rf $(OBJDIR) vmlinux.h
