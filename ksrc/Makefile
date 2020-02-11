
include ../config.mk

ifeq ($(KVER),)
KVER=$(shell uname -r)
endif
KMAJ=$(shell echo $(KVER) | awk -F'.' '{print $$1}')

ifeq ($(KDIR),)
KDIR=$(shell ../utils/get_path.sh -r $(KVER) -k)
endif
ifeq ($(BDIR),)
BDIR=$(shell ../utils/get_path.sh -r $(KVER) -b)
endif

# requires 4.16 and up; 5.0 for simplicity
# TO-DO: make a compile time check
ifneq ($(KMAJ),4)
EXTRA_DEFS=-DHAVE_INGRESS_IFINDEX
endif

OBJDIR = obj/

MODS += $(OBJDIR)execsnoop.o
MODS += $(OBJDIR)opensnoop.o

MODS += $(OBJDIR)pktdrop.o
MODS += $(OBJDIR)pktlatency.o

MODS += $(OBJDIR)xdp_l2fwd_kern.o
MODS += $(OBJDIR)xdp_dummy_kern.o

VPATH := .

# rule is based on samples/bpf/Makefile
CLANG = clang
LLC = llc

DEFS = -D__KERNEL__ -D__BPF_TRACING__  -D__TARGET_ARCH_x86 $(EXTRA_DEFS)

CFLAGS += -Wno-unused-value -Wno-pointer-sign 
CFLAGS += -Wno-compare-distinct-pointer-types 
CFLAGS += -Wno-gnu-variable-sized-type-not-at-end 
CFLAGS += -Wno-address-of-packed-member 
CFLAGS += -Wno-tautological-compare 
CFLAGS += -Wno-unknown-warning-option

INCLUDES  = -I$(LIBBPF_PATH)/usr/include
INCLUDES += -I$(KDIR)/arch/x86/include
INCLUDES += -I$(BDIR)/arch/x86/include/generated
INCLUDES += -I$(BDIR)/include 
INCLUDES += -I$(KDIR)/include 
INCLUDES += -I$(KDIR)/arch/x86/include/uapi 
INCLUDES += -I$(BDIR)/arch/x86/include/generated/uapi 
INCLUDES += -I$(KDIR)/include/uapi 
INCLUDES += -I$(BDIR)/include/generated/uapi 
INCLUDES += -I../include

SINCLUDES  = -include $(KDIR)/include/linux/kconfig.h
SINCLUDES += -include include/asm_goto_workaround.h

# this is to find stdarg.h. Ubuntu has this under x86_64-linux-gnu
# and Fedora is under x86_64-redhat-linux. Let's try 'find'.
GCCVER=$(shell gcc -v 2>&1 | awk '{if ($$0 ~ /gcc version/) {ver=split($$3,n,"."); print n[1]}}')
GCC_INC=$(shell find /usr/lib/gcc/x86_64-*linux*/$(GCCVER) -name include)
NOSTDINC_FLAGS = -nostdinc -isystem $(GCC_INC)

# newer LLC?
#LLC_FLAGS += -mattr=dwarfris

all: build $(MODS)

build:
	@mkdir -p $(OBJDIR)

$(OBJDIR)%.o: %.c
	$(CLANG) $(NOSTDINC_FLAGS) $(INCLUDES) \
		$(SINCLUDES) $(DEFS) $(CFLAGS) \
		-O2 -emit-llvm -c $< -o - | \
		 $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@

clean:
	@rm -rf $(OBJDIR)
