# SPDX-License-Identifier: GPL-2.0

include ../config.mk

ifneq (,$(BUILDDIR))
OBJDIR = $(BUILDDIR)/ksrc/obj/
else
OBJDIR = obj/
endif

MODS += $(OBJDIR)execsnoop.o
MODS += $(OBJDIR)execsnoop_legacy.o
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
DEFS = -D__KERNEL__ -D__BPF_TRACING__  -D__TARGET_ARCH_x86 $(EXTRA_DEFS)

CFLAGS += -g
CFLAGS += -Wno-unused-value -Wno-pointer-sign
CFLAGS += -Wno-compare-distinct-pointer-types
CFLAGS += -Wno-gnu-variable-sized-type-not-at-end
CFLAGS += -Wno-address-of-packed-member
CFLAGS += -Wno-tautological-compare
CFLAGS += -Wno-unknown-warning-option
CFLAGS += -fno-stack-protector

INCLUDES  = -I../include
INCLUDES += -I../libbpf/usr/include
INCLUDES += -I$(KSRC)/arch/x86/include
INCLUDES += -I$(KBLD)/arch/x86/include/generated
INCLUDES += -I$(KBLD)/include
INCLUDES += -I$(KSRC)/include
INCLUDES += -I$(KSRC)/arch/x86/include/uapi
INCLUDES += -I$(KBLD)/arch/x86/include/generated/uapi
INCLUDES += -I$(KSRC)/include/uapi
INCLUDES += -I$(KBLD)/include/generated/uapi

SINCLUDES  = -include $(KSRC)/include/linux/kconfig.h
SINCLUDES += -include include/asm_goto_workaround.h

# this is to find stdarg.h. Ubuntu has this under x86_64-linux-gnu
# and Fedora is under x86_64-redhat-linux. Let's try 'find'.
GCCVER=$(shell gcc -v 2>&1 | awk '{if ($$0 ~ /gcc version/) {ver=split($$3,n,"."); print n[1]}}')
GCC_INC=$(shell find /usr/lib/gcc/x86_64-*linux*/$(GCCVER) -name include)
NOSTDINC_FLAGS = -nostdinc -isystem $(GCC_INC)

all: build $(MODS)

build:
	@mkdir -p $(OBJDIR)

$(OBJDIR)%.o: %.c
	$(QUIET_CLANG)$(CLANG) $(NOSTDINC_FLAGS) $(INCLUDES) \
		$(SINCLUDES) $(DEFS) $(CFLAGS) \
		-O2 -emit-llvm $(CLANG_FLAGS) -c $< -o $@.cl
	$(QUIET_LLC)$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@ $@.cl
	@rm $@.cl

clean:
	@rm -rf $(OBJDIR)
