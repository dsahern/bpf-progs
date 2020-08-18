#!/bin/bash

BPFFS=/sys/fs/bpf
BPFTOOL=~/bin/bpftool

# public vlan
PVLAN=51

# VM data
VMID=4798884
VMNAME=Droplet-${VMID}
# public data
PMAC=12:41:da:80:1f:71
PV4=10.39.16.67
PV6=fd53:616d:6d60:5::f000

# VPC data
VMAC=12:30:6d:9f:6f:42
VV4=10.39.32.23

################################################################################
#
pr_msg()
{
	echo -e "\e[34m$*\e[00m"
}

run_cmd()
{
	local cmd="$*"

	echo
	echo -e "\e[31m${cmd}\e[00m"
	sudo $cmd
}

show_maps()
{
	echo
        echo -e "\e[31m${BPFTOOL} map sh\e[00m"
	sudo ${BPFTOOL} map sh | \
	awk 'BEGIN { skip = 0 } {
		if (skip) {
			skip--
		} else if ($2 == "lpm_trie") {
			skip = 1
		} else {
			print
		}
	}'
}

show_progs()
{
	echo
        echo -e "\e[31m${BPFTOOL} prog sh\e[00m"
	sudo ${BPFTOOL} prog sh | \
	awk 'BEGIN { skip = 0 } {
		if (skip) {
			skip--
		} else if ($2 == "cgroup_skb") {
			skip = 2
		} else {
			print
		}
	}'
}

show_status()
{
	show_maps
	show_progs
	run_cmd ${BPFTOOL} net sh
}

do_reset()
{
	sudo rm -rf ${BPFFS}/map
	sudo rm -rf ${BPFFS}/prog
	sudo mkdir ${BPFFS}/map
	sudo mkdir ${BPFFS}/prog

	for d in eth0 eth1
	do
		sudo ${BPFTOOL} net detach xdp dev ${d}
		sudo ethtool -K ${d} hw-tc-offload on
		sudo ethtool -K ${d} rxvlan off
	done
}

################################################################################
# start

do_reset >/dev/null 2>&1

echo
pr_msg "Create ports map"
pr_msg "- global map used for bulking redirected packets"

run_cmd ${BPFTOOL} map create ${BPFFS}/map/xdp_fwd_ports \
       type devmap_hash key 4 value 8 entries 512 name xdp_fwd_ports

echo
pr_msg "Add entries to the egress port map for eth0 (index 2) and eth1 (index 3)"
run_cmd ${BPFTOOL} map update pinned ${BPFFS}/map/xdp_fwd_ports \
	key hex 2 0 0 0 value hex 2 0 0 0 0 0 0 0
run_cmd ${BPFTOOL} map update pinned ${BPFFS}/map/xdp_fwd_ports \
	key hex 3 0 0 0 value hex 3 0 0 0 0 0 0 0

echo
pr_msg "load l2fwd program and attach to eth0 and eth1"

run_cmd ${BPFTOOL} prog load ksrc/obj/xdp_l2fwd.o ${BPFFS}/prog/xdp_l2fwd \
    map name xdp_fwd_ports name xdp_fwd_ports
run_cmd ${BPFTOOL} net attach xdp pinned ${BPFFS}/prog/xdp_l2fwd dev eth0
run_cmd ${BPFTOOL} net attach xdp pinned ${BPFFS}/prog/xdp_l2fwd dev eth1

echo
pr_msg "Add FDB and port map entries for this VM"
run_cmd src/bin/xdp_l2fwd -v ${PVLAN} -m ${PMAC} -d tapext${VMID}
run_cmd src/bin/xdp_l2fwd -P
