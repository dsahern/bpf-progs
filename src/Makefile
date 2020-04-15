
include ../config.mk

OBJDIR = obj/

MODS += $(OBJDIR)execsnoop
MODS += $(OBJDIR)opensnoop
MODS += $(OBJDIR)cgroup_sock

MODS += $(OBJDIR)netmon
MODS += $(OBJDIR)pktlatency
MODS += $(OBJDIR)ovslatency
MODS += $(OBJDIR)net_rx_action

MODS += $(OBJDIR)xdp_dummy

VPATH := .

CC = gcc
CFLAGS = -O2 -g -Wall

INCLUDES  = -I../include -I../include/uapi
INCLUDES += -I../include/tools

ifneq (,$(LIBBPF_PATH))
LIBBPF=$(LIBBPF_PATH)/usr/lib64/libbpf.a
INCLUDES += -I$(LIBBPF_PATH)/usr/include
else
LIBBPF=-lbpf
endif
LIBS=$(LIBBPF) -lelf

COMMON += $(OBJDIR)timestamps.o
COMMON += $(OBJDIR)libbpf_helpers.o
COMMON += $(OBJDIR)str_utils.o
COMMON += $(OBJDIR)rbtree.o
COMMON += $(OBJDIR)parse_pkt.o
COMMON += $(OBJDIR)print_pkt.o
COMMON += $(OBJDIR)ksyms.o

all: build common $(MODS)

build:
	@mkdir -p $(OBJDIR)

common: $(COMMON)

$(OBJDIR)%: $(OBJDIR)%.o $(COMMON)
	$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) $^ -o $@ $(LIBS)

$(OBJDIR)xdp_%: $(OBJDIR)xdp_%_user.o $(COMMON)
	$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) $^ -o $@ $(LIBS)

$(OBJDIR)%.o: %.c
	$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) -c $^ -o $@

$(OBJDIR)netmon: $(OBJDIR)netmon.o $(COMMON)
	$(CC) $(INCLUDES) $(DEFS) $(CFLAGS) $^ -o $@ $(LIBS) -lpcap

clean:
	@rm -rf obj
