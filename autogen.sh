#!/bin/sh
set -x
ACLOCAL=${ACLOCAL:-aclocal}; export ACLOCAL
AUTOMAKE=${AUTOMAKE:-automake}; export AUTOMAKE
AUTOCONF=${AUTOCONF:-autoconf}; export AUTOCONF
LIBTOOLIZE=${LIBTOOLIZE:-libtoolize}; export LIBTOOLIZE
AUTOHEADER=${AUTOHEADER:-autoheader}; export AUTOHEADER
GETTEXTIZE=${GETTEXTIZE:-gettextize}; export GETTEXTIZE

cd argp &&
rm -vf config.cache &&
rm -rvf autom4te.cache &&
$ACLOCAL &&
$AUTOCONF &&
$AUTOMAKE --add-missing &&
$AUTOHEADER &&
cd .. &&
rm -vf config.cache &&
rm -rvf autom4te.cache &&
$GETTEXTIZE --intl --force &&
$ACLOCAL -I m4 -I argp
$LIBTOOLIZE --force --automake
$ACLOCAL -I m4 -I argp
$AUTOCONF
$AUTOMAKE --gnits --add-missing
$AUTOHEADER
: 'You can now run CFLAGS="-g -pedantic -Wall" ./configure --enable-maintainer-mode and then make.'
