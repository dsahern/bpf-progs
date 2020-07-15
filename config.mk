ifeq ("$(origin V)", "command line")
  VERBOSE = $(V)
endif
ifndef VERBOSE
  VERBOSE = 0
endif
ifeq ($(VERBOSE),1)
  Q =
else
  Q = @
endif

ifeq ($(VERBOSE), 0)
  QUIET_CC       = @echo '    CC       '$@;
  QUIET_LINK     = @echo '    LINK     '$@;
  QUIET_CLANG    = @echo '    CLANG    '$@;
  QUIET_LLC      = @echo '    LLC      '$@;
endif

# autodetected (if possible). Set here for override
#KVER=$(shell uname -r)
#KDIR=/lib/modules/$(KVER)/source
#KDIR=/usr/src/linux-headers-$(KVER)/
#BDIR=/lib/modules/$(KVER)/build
#KVER=4.14.91-1-generic

# Where to find libbpf and include files. Default is
# to use the install from github repo to ./libbpf.
# Path is relative to src and ksrc directories.
PWD := $(shell pwd)
LIBBPF_PATH=$(PWD)/../libbpf
