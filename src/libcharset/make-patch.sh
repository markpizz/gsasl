#!/bin/sh

if test $# = 1 ; then 
  ORIGINAL=$1
else
  echo "Usage: make-patch.sh /path/to/libcharset" 1>&2
  exit 1
fi

if test -f $ORIGINAL/lib/localcharset.c ; then : ; else
  echo "Usage: make-patch.sh /path/to/libcharset" 1>&2
  exit 1
fi

VERSION=`grep VERSION= $ORIGINAL/configure.in | sed s/VERSION=//`

echo "# Patch against libcharset version $VERSION" > libcharset-gsasl.patch

for i in localcharset.c ref-add.sin ref-del.sin ; do
  diff -u $ORIGINAL/lib/$i $i >> libcharset-gsasl.patch
done

diff -u $ORIGINAL/include/libcharset.h.in libcharset.h >> libcharset-gsasl.patch
