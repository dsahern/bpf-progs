#!/bin/bash

CMD=${0##*/}

# default path for bpftool
BPFTOOL="sudo $HOME/bin/bpftool"

# default path for object file
OBJFILE=$HOME/bpf-obj/xdp_l2fwd_kern.o

PROG_NAME="xdp_l2fwd_prog"
FDB_MAP_NAME="fdb_map"
PORTS_MAP_NAME="xdp_fwd_ports"

# default path for pinning program
BPFFS_PATH=/sys/fs/bpf/${PROG_NAME}

# lines expected to have the format:
#     name     vlan     mac     device
# if vlans are not used, set column to 0
# vlan is in HEX without leading 0x
CONFIG=$HOME/.vm-config

################################################################################
# helpers

get_prog_id()
{
	local name=$1
	local id

	id=$(${BPFTOOL} prog sh | awk -v name=$name '{ if ($3 == "name" && $4 == name) print $1 }')
	if [ -z "$id" ]
	then
		echo "Failed to find index of program \"$name\"" >&2
		return 1
	fi

	if [ $(echo "$id" | wc -l) -gt 1 ]
	then
		echo "Found multiple programs with same name" >&2
		return 1
	fi

	echo ${id/:/}

	return 0
}

get_map_id()
{
	local name=$1
	local id

	id=$(${BPFTOOL} map sh | awk -v name=$name '{ if ($3 == "name" && $4 == name) print $1 }')
	if [ -z "$id" ]
	then
		echo "Failed to find index of map \"$name\"" >&2
		return 1
	fi

	if [ $(echo "$id" | wc -l) -gt 1 ]
	then
		echo "Found multiple maps with same name" >&2
		return 1
	fi

	echo ${id/:/}

	return 0
}

map_dump()
{
	local desc="$1"
	local mapid

	mapid=$(get_map_id ${desc})
	exit_non_zero_rc $?

	echo
	echo "Map: $desc"
	${BPFTOOL} map dump id ${mapid} | grep -v '<no entry>'
}

get_dev_idx()
{
	local name=$1
	local p="/sys/class/net/${name}/ifindex"
	local idx

	if [ ! -f $p ]
	then
		echo "device \"$name\" does not exist" >&2
		return 1
	fi

	idx=$(cat $p)
	if [ -z "${idx}" ]
	then
		echo "Failed to get device index for \"$name\"" >&2
		return 1
	fi

	echo $idx

	return 0
}

check_offload()
{
	local dev=$1
	local status

	status=$(ethtool -k ${dev} | awk '$1 == "rx-vlan-offload:" {print $2}')
	if [ "$status" = "on" ]
	then
		echo
		echo "WARNING: vlan offload enabled in Rx path. Disable with:"
		echo "         ethtool -K ${dev} rxvlan off"
	fi
}

################################################################################
# actions

load_usage="${CMD} load [obj-file]"

do_load()
{
	local obj

	if [ "${1}" = "-h" ]
	then
		echo ${load_usage}
		exit 0
	fi

	obj=$1
	[ -z "$obj" ] && obj=${OBJFILE}

	sudo stat ${BPFFS_PATH} >/dev/null 2>&1
	if [ $? -eq 0 ]
	then
		echo "program already loaded" >&2
		return 1
	fi

	${BPFTOOL} prog load ${obj} ${BPFFS_PATH}
}

unload_usage="${CMD} unload"

do_unload()
{
	local obj

	if [ "${1}" = "-h" ]
	then
		echo ${unload_usage}
		exit 0
	fi

	obj=$1
	[ -z "$obj" ] && obj=${OBJFILE}

	sudo stat ${BPFFS_PATH} >/dev/null 2>&1
	if [ $? -ne 0 ]
	then
		echo "program not loaded" >&2
		return 1
	fi

	sudo rm -f ${BPFFS_PATH}
}

attach_usage="${CMD} attach host-device(s)"

do_attach()
{
	local dev
	local progid

	if [ "${1}" = "-h" ]
	then
		echo ${attach_usage}
		return 0
	fi

	if [ -z "$1" ]
	then
		echo ${attach_usage} >&2
		return 1
	fi

	progid=$(get_prog_id ${PROG_NAME})
	exit_non_zero_rc $?

	for dev in $*
	do
		${BPFTOOL} net attach xdp id ${progid} dev ${dev}
	done
}

detach_usage="${CMD} detach host-device(s)"

do_detach()
{
	local dev

	if [ "${1}" = "-h" ]; then
		echo ${detach_usage}
		return 0
	fi

	if [ -z "$1" ]; then
		echo ${detach_usage} >&2
		return 1
	fi

	for dev in $*
	do
		${BPFTOOL} net detach xdp dev ${dev}
	done

}

add_usage="$CMD add [-d device -m mac -v vlan | vm-name]"

do_add()
{
	local devmap
	local fdbmap
	local dev
	local devidx
	local mac
	local vlan
	local vm
	local tmp

	while getopts :d:m:v:h o
	do
		case $o in
		d) dev=$OPTARG;;
		m) mac=$OPTARG;;
		v) vlan=$OPTARG;;
		h) echo "${add_usage}"; exit 0;;
		*) echo "${add_usage}" >&2; exit 1;;
		esac
	done
	shift $(($OPTIND-1))

	vm=$1

	if [ -n "${vm}" ]
	then
		tmp=$(awk -v name=${vm} '$1 == name {print}' $CONFIG)
		set -- ${tmp}

		vlan=$2
		mac=$3
		dev=$4
		if [ -z "${vlan}" -o -z "${mac}" -o -z "${dev}" ]
		then
			echo "Invalid config file entry for ${vm}"
			exit 1
		fi
	elif [ -z "${vlan}" -o -z "${mac}" -o -z "${dev}" ]
	then
		echo "${add_usage}"
		exit 1
	fi

	if [ ${vlan} -gt 4095 ]
	then
		echo "Invalid vlan"
		return 1
	fi
	# convert vlan to 4 digit hex
	vlan=$(printf "%04x" ${vlan})

	devidx=$(get_dev_idx ${dev})
	exit_non_zero_rc $?
	devidx=$(printf "%08x" ${devidx})
	dev="${devidx:6:2} ${devidx:4:2} ${devidx:2:2} ${devidx:0:2}"

	# lookup device and fdb maps
	devmap=$(get_map_id ${PORTS_MAP_NAME})
	exit_non_zero_rc $?
	fdbmap=$(get_map_id ${FDB_MAP_NAME})
	exit_non_zero_rc $?

	${BPFTOOL} map update id ${devmap} key hex ${dev} value hex ${dev}
	if [ $? -eq 0 ]
	then
		${BPFTOOL} map update id ${fdbmap} key hex ${mac//:/ } ${vlan:2:2} ${vlan:0:2} value hex ${dev}
		if [ $? -ne 0 ]
		then
			echo "Failed to add entry to fdb map"
			return 1
		fi
	else
		echo "Failed to add entry to port map"
		return 1
	fi

	return 0
}

delete_usage="$CMD delete [-d device -m mac -v vlan | vm-name]"

do_delete()
{
	local devmap
	local fdbmap
	local dev
	local devidx
	local mac
	local vlan
	local vm
	local tmp

	while getopts :d:m:v:h o
	do
		case $o in
		d) dev=$OPTARG;;
		m) mac=$OPTARG;;
		v) vlan=$OPTARG;;
		h) echo "${delete_usage}"; exit 0;;
		*) echo "${delete_usage}" >&2; exit 1;;
		esac
	done
	shift $(($OPTIND-1))

	vm=$1

	if [ -n "${vm}" ]
	then
		tmp=$(awk -v name=${vm} '$1 == name {print}' $CONFIG)
		set -- ${tmp}

		vlan=$2
		mac=$3
		dev=$4
		if [ -z "${vlan}" -o -z "${mac}" -o -z "${dev}" ]
		then
			echo "Invalid config file entry for ${vm}"
			exit 1
		fi
	elif [ -z "${vlan}" -o -z "${mac}" -o -z "${dev}" ]
	then
		echo "${delete_usage}"
		exit 1
	fi
	# convert vlan to 4 digit hex
	vlan=$(printf "%04x" ${vlan})

	devidx=$(get_dev_idx ${dev})
	exit_non_zero_rc $?
	devidx=$(printf "%08x" ${devidx})
	dev="${devidx:6:2} ${devidx:4:2} ${devidx:2:2} ${devidx:0:2}"

	# lookup device and fdb maps
	devmap=$(get_map_id ${PORTS_MAP_NAME})
	exit_non_zero_rc $?
	fdbmap=$(get_map_id ${FDB_MAP_NAME})
	exit_non_zero_rc $?

	${BPFTOOL} map delete id ${devmap} key hex ${dev}
	${BPFTOOL} map delete id ${fdbmap} key hex ${mac//:/ } ${vlan:2:2} ${vlan:0:2}
}

fdb_dump()
{
	local mapid

	mapid=$(get_map_id ${FDB_MAP_NAME})
	exit_non_zero_rc $?

	echo
	echo "FDB entries:"
	${BPFTOOL} map dump id ${mapid} | egrep '^key:' | \
	while read key o1 o2 o3 o4 o5 o6 v1 v2 value i1 i2 i3 i4
	do
		vlan="0x${v2}${v1}"
		vlan=$(printf "%d" $vlan)
		idx="0x${i4}${i3}${i2}${i1}"
		idx=$(printf "%d" $idx)
		echo "    vlan ${vlan} mac ${o1}:${o2}:${o3}:${o4}:${o5}:${o6} --> ${idx}"
	done
}

ports_dump()
{
	local mapid

	mapid=$(get_map_id ${PORTS_MAP_NAME})
	exit_non_zero_rc $?

	echo
	echo "Port entries:"
	${BPFTOOL} map dump id ${mapid} | egrep '^key:' | grep -v '<no entry>' | \
	while read key o1 o2 o3 o4 value i1 i2 i3 i4
	do
		idx="0x${o4}${o3}${o2}${o1}"
		idx=$(printf "%d" $idx)
		port="0x${i4}${i3}${i2}${i1}"
		port=$(printf "%d" $port)
		echo "    ${idx} --> device ${port}"
	done
}

do_dump()
{
	fdb_dump
	ports_dump
}

do_stats()
{
	map_dump "stats_map"
}

do_status()
{
	local progid
	local devs
	local d

	progid=$(get_prog_id ${PROG_NAME} 2>/dev/null)
	if [ $? -ne 0 ]
	then
		echo "${PROG_NAME} is not loaded"
		return 0
	fi

	devs=$(ip -o li show | awk '$0 ~ "prog/xdp id '${progid}'"{printf "%s ", $2}')
	if [ -n "${devs}" ]
	then
		devs="${devs//:/}"
		echo "${PROG_NAME} is attached to ${devs//:/}"

		for d in ${devs}
		do
			check_offload ${d}
		done
	else
		echo "${PROG_NAME} is loaded but not attached to any devices"
	fi
}

################################################################################

exit_non_zero_rc()
{
	local rc=$1

	[ $rc -eq 0 ] && return

	exit 1
}

################################################################################
#

usage()
{
	cat <<EOF
${CMD} ACTION [ ARGS ]

	load    - loads l2fwd program
	unload  - unloads l2fwd program
	attach  - attaches program to device
	detach  - detaches program to device
	add     - add fdb entry for VM
	del     - delete fdb entry for VM
	dump    - dump fdb map
	status  - status of l2fwd
EOF
}

################################################################################
# main

ACTION=$1
shift

case "${ACTION}" in
	load)			do_load $*   ;;
	unload)			do_unload $* ;;
	add)			do_add $*    ;;
	attach)			do_attach $* ;;
	del|delete|rem|remove)	do_delete $* ;;
	detach)			do_detach $* ;;
	dump)			do_dump $*   ;;
	stats)			do_stats $*  ;;
	status)			do_status $* ;;
	*)			usage; exit 1;;
esac
