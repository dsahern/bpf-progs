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

	sudo virsh list 2>/dev/null | grep -q ${VMNAME}
	if [ $? -eq 0 ]; then
		sudo virsh resume ${VMNAME} >/dev/null 2>&1
		sudo virsh shutdown ${VMNAME} >/dev/null 2>&1
	fi
}

################################################################################
# start

do_reset >/dev/null 2>&1

################################################################################
clear

echo
pr_msg "start point - only systemd based cgroup programs loaded"
show_status

read ans

################################################################################
clear

echo
pr_msg "Create vm info map"
pr_msg "- global map with data about VMs; all VM based programs will access"
pr_msg "  by tap device index to retrieve VM specific data"
pr_msg "- map holds data about all interfaces - public, private and mgmt"

run_cmd ${BPFTOOL} map create ${BPFFS}/map/vm_info \
       type hash key 4 value 32 entries 500 name vm_info_map

echo
pr_msg "Create ports map"
pr_msg "- global map used for bulking redirected packets"

run_cmd ${BPFTOOL} map create ${BPFFS}/map/xdp_fwd_ports \
       type devmap_hash key 4 value 8 entries 512 name xdp_fwd_ports

show_maps

echo
pr_msg "Add entries to the egress port map for eth0 (index 2) and eth1 (index 3)"
run_cmd ${BPFTOOL} map update pinned ${BPFFS}/map/xdp_fwd_ports \
	key hex 2 0 0 0 value hex 2 0 0 0 0 0 0 0
run_cmd ${BPFTOOL} map update pinned ${BPFFS}/map/xdp_fwd_ports \
	key hex 3 0 0 0 value hex 3 0 0 0 0 0 0 0

read ans


################################################################################
clear

echo
pr_msg "load l2fwd program and attach to eth0 and eth1"

run_cmd ${BPFTOOL} prog load ksrc/obj/xdp_l2fwd.o ${BPFFS}/prog/xdp_l2fwd \
    map name xdp_fwd_ports name xdp_fwd_ports
run_cmd ${BPFTOOL} net attach xdp pinned ${BPFFS}/prog/xdp_l2fwd dev eth0
run_cmd ${BPFTOOL} net attach xdp pinned ${BPFFS}/prog/xdp_l2fwd dev eth1

show_status
read ans

################################################################################
clear
echo
pr_msg "VM is started, but paused - to get tap devices created"
run_cmd sudo virsh start --paused ${VMNAME}

# keep vhost threads on cpus 60 and under
ps -e -o "pid comm" | grep vhost |
while read p c; do
	egrep "Cpus_allowed:" /proc/${p}/status | grep -q '00000000,02aaaaaa,aa8002aa'
	if [ $? -eq 0 ]; then
		sudo taskset -pc 1,3,5,7,9,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57 $p >/dev/null 2>&1
	else
		sudo taskset -pc 0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44 $p >/dev/null 2>&1
	fi
done

echo
pr_msg "Add entries to VM info map"
run_cmd src/obj/vm_info -i ${VMID} -d tapext${VMID} -v 51 -m ${PMAC} -4 ${PV4} -6 ${PV6}
run_cmd src/obj/vm_info -i ${VMID} -d tapint${VMID} -m ${VMAC} -4 ${VV4}
run_cmd sudo src/obj/vm_info -P
read ans

################################################################################
clear
echo
pr_msg "Create Rx and Tx ACL maps and load programs for VM's devices"
run_cmd ${BPFTOOL} map create ${BPFFS}/map/tx_acl_${VMID} \
    type hash key 4 value 36 entries 32 name tx_acl_${VMID}

run_cmd ${BPFTOOL} map create ${BPFFS}/map/rx_acl_${VMID} \
    type hash key 4 value 36 entries 32 name rx_acl_${VMID}

echo
pr_msg "At this point ACL entries can be created for this VM"

read ans
echo
pr_msg "Example: block VM from sending email via smtp"
run_cmd src/obj/xdp_acl -p ${BPFFS}/map/rx_acl_${VMID} -- "proto=tcp,dport=25"
run_cmd src/obj/xdp_acl -p ${BPFFS}/map/rx_acl_${VMID} -- "proto=udp,dport=25"
echo
pr_msg "Example: block VM from reaching 80/tcp (easy to test)"
run_cmd src/obj/xdp_acl -p ${BPFFS}/map/rx_acl_${VMID} -- "proto=tcp,dport=80"
run_cmd src/obj/xdp_acl -p ${BPFFS}/map/rx_acl_${VMID} -P
echo
pr_msg "Example: block access to VM port 80/tcp"
run_cmd src/obj/xdp_acl -p ${BPFFS}/map/tx_acl_${VMID} -- "proto=tcp,dport=80"
run_cmd src/obj/xdp_acl -p ${BPFFS}/map/tx_acl_${VMID} -P

read ans

################################################################################
clear
echo
pr_msg "Load ACL programs for this VM and attach to tap device"
run_cmd ${BPFTOOL} prog loadall \
    ksrc/obj/acl_vm_tx.o ${BPFFS}/prog/acl_tx_${VMID} \
    map name __vm_info_map name vm_info_map \
    map name __tx_acl_map  name tx_acl_${VMID}

run_cmd ${BPFTOOL} prog loadall \
    ksrc/obj/xdp_vmegress.o ${BPFFS}/prog/vm_egress_${VMID} \
    map name __egress_ports name xdp_fwd_ports \
    map name __vm_info_map name vm_info_map \
    map name __acl_map  name rx_acl_${VMID}

run_cmd ${BPFTOOL} net attach xdp \
    pinned ${BPFFS}/prog/vm_egress_${VMID}/xdp_egress dev tapext${VMID}

show_status

read ans

################################################################################
clear
echo
pr_msg "Add FDB and port map entries for this VM"
pr_msg "- adds Tx ACL (packets to VM) to map entry"
run_cmd src/obj/xdp_l2fwd -v ${PVLAN} -m ${PMAC} -d tapext${VMID} \
    -p ${BPFFS}/prog/acl_tx_${VMID}/xdp_devmap_acl_vm_tx

run_cmd src/obj/xdp_l2fwd -P

echo
pr_msg "Resume VM"
run_cmd sudo virsh resume ${VMNAME}
