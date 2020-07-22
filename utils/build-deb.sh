#!/bin/bash

set -e
set -x

KERNEL_VER=$1
[ -z "${KERNEL_VER}" ] && KERNEL_VER=$(uname -r)

# When linux-headers is installed
KERNDIR=/usr/src/linux-headers-$KERNEL_VER
if [ ! -e $KERNDIR -a -e /lib/modules/${KERNEL_VER}/build ]; then
    # When the prebuilt sources are installed
    KERNDIR=/build/linux
elif [ ! -e $KERNDIR ]; then
    echo error: $KERNDIR does not exist
    exit 1
fi

DEBNAME=dsa-bpf-progs
PACKAGE_NAME=dsa-bpf-progs
PACKAGE_VERSION=1.0
PACKAGE_REVISION=$(git rev-parse --short HEAD)
PACKAGE_REVISION="1+dsa~${PACKAGE_REVISION}"

SRCDIR=$(pwd)
BUILDDIR=${SRCDIR}/build

#
# Create debian packaging
#
rm -rf $BUILDDIR
mkdir -p $BUILDDIR/debian
mkdir -p $BUILDDIR/debian/build

echo 10 > $BUILDDIR/debian/compat

DATE=$(date '+%a, %d %b %Y %T %z')

cat > $BUILDDIR/debian/changelog <<EOF
$PACKAGE_NAME ($PACKAGE_VERSION-$PACKAGE_REVISION) UNRELEASED; urgency=low

  Build

 -- testing <noone@some.com>  $DATE
EOF

cat > $BUILDDIR/debian/control <<EOF
Source: $PACKAGE_NAME
Section: net
Priority: extra
Maintainer: testing <noone@some.com>
Build-Depends: debhelper (>= 5.0.37),
               libpcap-dev,
               clang,
               llvm,
               gcc,
               make,
               libelf-dev
Standards-Version: 3.7.3

Package: $DEBNAME
Architecture: any
Provides: $DEBNAME
Description: $PACKAGE_NAME userspace
 This package contains the $PACKAGE_NAME userspace commands.

Package: $DEBNAME-$KERNEL_VER
Architecture: any
Provides: $DEBNAME
Description: $PACKAGE_NAME bpf modules
 This package contains the $PACKAGE_NAME bpf modules for
 the kernel-image-$KERNEL_VER package.
 .
 If you compiled a custom kernel, you will most likely need to compile
 a custom version of this module as well.
EOF

cat > $BUILDDIR/debian/rules <<EOF
#! /usr/bin/make -f

PACKAGE_NAME=$PACKAGE_NAME
KVERS=$KERNEL_VER
KSRC=$KERNDIR
PKGNAME=\$(PACKAGE_NAME)-\$(KVERS)

.PHONY: all
KDSTDIR = debian/${DEBNAME}-${KERNEL_VER}/usr/local/lib/bpf-obj/\$(KVERS)/${PACKAGE_VERSION}-${PACKAGE_REVISION}
DSTDIR = debian/${DEBNAME}/usr/local/bin
all:
	dh_testdir
	dh_testroot
	dh_prep
EOF

# Emit make commands
cat >> $BUILDDIR/debian/rules <<EOF
	cd $SRCDIR && make BUILDDIR=$BUILDDIR/debian/build KVER=${KERNEL_VER}
	install -d -m755 \$(KDSTDIR)
	install -m644 $BUILDDIR/debian/build/ksrc/obj/* \$(KDSTDIR)/
	install -d -m755 \$(DSTDIR)
	install -m644 $BUILDDIR/debian/build/src/bin/* \$(DSTDIR)/
	dh_installmodules
	dh_installdocs
	dh_installchangelogs
	dh_compress
	dh_fixperms
	dh_installdeb
	dh_gencontrol
	dh_md5sums
	dh_builddeb
EOF

echo 'usr/local/bin/*' > $BUILDDIR/debian/$DEBNAME.install
echo "usr/lib/bpf-obj/*/${KVERS}/${PACKAGE_VERSION}-${PACKAGE_REVISION}"  > $BUILDDIR/debian/$DEBNAME-$KERNEL_VER.install

chmod a+x $BUILDDIR/debian/rules

# FIXME: Create debian/copyright?

# Build .deb package
(cd $BUILDDIR; fakeroot debian/rules all)
