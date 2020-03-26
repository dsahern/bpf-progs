# bpf-progs

Hopefully this repository is self contained now. It compiles cleanly on Ubuntu
18.04 for kernel versions 4.14, 4.15, 5.3 and 5.5+.
```
apt-get install clang llvm gcc make libelf-dev

install linux-headers for kernel version.
```
This code is structured to make the data collection as much of a template
as possible, so new programs can copy-modify and focus on the analysis at
hand as much as possible.

## pktdrop

pktdrop is similar to dropwatch, but examines the packet headers and summarizes
drops by a number of options:
- source mac,
- destination mac,
- IPv4 source IP,
- IPv4 destination IP, and
- network namespaces.

Network namespace support is best effort in determining the association. It has
been used to look at drops for containers.

### show packet drops sorted by destination IP
sudo src/obj/pktdrop -s dip

### show packet drops sorted by destination mac
sudo src/obj/pktdrop -s dmac

### TO-DO:
- support for drops at XDP layer
 
## pktlatency

pktlatency is used to examine the overhead of the host networking stack in
pushing packets to userspace. At the moment it is focused on virtual machines
using tap devices and vhost. The program requires a NIC with PTP support
(e.g., mlx5). I am very much new to PTP, so there very well could be some
bugs here.

It too was just renamed, from skblatency to pktlatency, in hopes of adding
support for packets pushed to a VM using XDP redirect.

### example
sudo src/obj/pktlatency

## ovslatency

ovslatency measures the time to run ovs\_vport\_receive which is the primary
workhorse for the OVS rx\_handler, netdev\_frame\_hook.

## execsnoop / opensnoop

execsnoop and opensnoop are ebpf versions of what I previously would do using
kernel modules. bcc's python version inspired me to do the deep dive on bpf
attached to kprobes and tracepoints to get the same intent with ebpf.

### examples
sudo src/obj/execsnoop
sudo src/obj/opensnoop

## XDP L2 forwarding

xdp\_l2fwd handles Layer 2 forwarding between an ingress device (e.g., host
devices) and egress device (e.g., tap device for VMs). Userspace populates
an FDB (hash map) with \<vlan,dmac> pairs returning an index into a device
map which contains the device to receive the packet. Lifecycle is managed by
scripts/xdp\_l2fwd.sh.

This program is used for the netdev 0x14 tutorial, XDP and the cloud: Using
XDP on hosts and VMs https://netdevconf.info/0x14/session.html?tutorial-XDP-and-the-cloud

## Dummy XDP program

xdp\_dummy is a dummy XDP program that just returns XDP\_PASS.
