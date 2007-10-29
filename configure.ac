dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 Simon Josefsson.
#
# This file is part of GNU SASL.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ(2.61)
AC_INIT([gsasl], [0.2.23], [bug-gsasl@gnu.org])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.10])
AC_CONFIG_HEADERS(config.h)
AB_INIT

# Internationalization.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.16.1)

# Checks for programs.
AC_PROG_CC
gl_EARLY
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(DIA, dia, $missing_dir)
AM_MISSING_PROG(EPSTOPDF, epstopdf, $missing_dir)

# Checks for header files.
AC_CHECK_HEADERS(sys/poll.h sys/time.h)
AC_CHECK_HEADERS(netdb.h netinet/in.h pwd.h errno.h)

# Checks for library functions.
AC_SEARCH_LIBS(socket, socket)
AC_CHECK_FUNCS(getpwuid)

# Allow disabling of obsolete stuff.
AC_ARG_ENABLE(obsolete,
  AS_HELP_STRING([--disable-obsolete], [disable backwards compatibility code]),
    obsolete=$enableval)
if test "$obsolete" = "no"; then
  AC_DEFINE(GSASL_NO_OBSOLETE, 1,
    [Define to 1 if you don't want backwards compatibility code.])
else
  obsolete=yes
fi
AC_MSG_CHECKING([if backwards compatibility code should be present])
AC_MSG_RESULT($obsolete)
AM_CONDITIONAL(OBSOLETE, test "$obsolete" = "yes")

# Check for gnutls
AC_ARG_WITH(gnutls,
  AS_HELP_STRING([--without-gnutls], [disable GnuTLS support]),
	gnutls=$withval, gnutls=yes)
if test "$gnutls" != "no"; then
  AC_LIB_HAVE_LINKFLAGS(gnutls,, [#include <gnutls/gnutls.h>],
    [gnutls_certificate_verify_peers2 (0, 0);])
fi
if test "$ac_cv_libgnutls" != yes; then
  gnutls=no
  AC_MSG_WARN([GnuTLS not found.  STARTTLS support disabled.])
fi
AC_MSG_CHECKING([if STARTTLS support via GnuTLS should be built])
AC_MSG_RESULT($gnutls)

# For gnulib stuff in gl/.
gl_INIT

# Check for gtk-doc.
GTK_DOC_CHECK(1.1)

# Set up the library.
AC_CONFIG_SUBDIRS(lib)

# Run self-tests under valgrind?
if test "$cross_compiling" = no; then
  AC_CHECK_PROGS(VALGRIND, valgrind)
fi
if test -n "$VALGRIND" && $VALGRIND true > /dev/null 2>&1; then
  opt_valgrind_tests=yes
else
  opt_valgrind_tests=no
  VALGRIND=
fi 
AC_MSG_CHECKING([whether self tests are run under valgrind])
AC_ARG_ENABLE(valgrind-tests,
	AS_HELP_STRING([--enable-valgrind-tests],
                       [run self tests under valgrind]),
  opt_valgrind_tests=$enableval)
AC_MSG_RESULT($opt_valgrind_tests)

# We are done.
AC_CONFIG_FILES(Makefile po/Makefile.in \
		doc/Makefile doc/reference/Makefile doc/doxygen/Doxyfile \
		gl/Makefile src/Makefile examples/Makefile tests/Makefile)
AC_OUTPUT
