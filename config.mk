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
