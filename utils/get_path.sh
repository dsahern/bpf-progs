#!/bin/bash
#
# script to find kernel paths

find_kdir()
{
	local p

	# Fedora, Redhat and custom kernels
	if [ -e /lib/modules/${KVER}/source ]; then
		p="/lib/modules/${KVER}/source"
	elif [ -e /usr/src/linux-headers-${KVER} ]; then
		p="/usr/src/linux-headers-${KVER}"
	else
		return 1
	fi

	echo $p
	return 0
}

find_bdir()
{
	local p

	if [ -e /lib/modules/${KVER}/build ]; then
		p=/lib/modules/${KVER}/build
	else
		return 1
	fi

	echo $p
	return 0
}

while getopts :kbr: o
do
	case $o in
		k) find_kdir;;
		b) find_bdir;;
		r) KVER=$OPTARG;;
		*) echo "unknown option";;
	esac
done
