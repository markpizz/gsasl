dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
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
AC_INIT([GNU SASL], [0.2.30], [bug-gsasl@gnu.org], [gsasl])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.10 -Wall -Werror -Wno-override])
AC_CONFIG_HEADERS(config.h)

# Checks for programs.
AC_PROG_CC
gl_EARLY
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(DIA, dia, $missing_dir)
AM_MISSING_PROG(EPSTOPDF, epstopdf, $missing_dir)

# Internationalization.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.17)

# Checks for header files.
AC_CHECK_HEADERS(pwd.h)

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

# Check for gtk-doc.
GTK_DOC_CHECK(1.1)

# For gnulib stuff in gl/.
gl_INIT

sj_VALGRIND

# Disable useless warnings.
W=
W="$W -Wsystem-headers"         # Don't let system headers trigger warnings.
W="$W -Wpadded"                 # Our structs are not padded.
W="$W -Wundef"                  # warns on '#if GNULIB_PORTCHECK' etc in gnulib
W="$W -Wc++-compat"             # We don't care strongly about C++ compilers
W="$W -Wswitch-enum"            # Too many warnings for now
W="$W -Wconversion"             # Too many warnings for now
W="$W -Wsign-conversion"        # Too many warnings for now
W="$W -Wtraditional"            # Warns on #elif which we use often
W="$W -Wtraditional-conversion" # Too many warnings for now
W="$W -Wunreachable-code"       # Too many false positives
gl_WARN_SUPPORTED([WARNINGS])
gl_WARN_COMPLEMENT(WARNINGS, [$WARNINGS], [$W])

for w in $WARNINGS; do
  gl_WARN_ADD([$w])
done
gl_WARN_ADD([-Wno-missing-field-initializers])
gl_WARN_ADD([-Wno-unused-parameter])
gl_WARN_ADD([-Wno-sign-compare])
gl_WARN_ADD([-Wno-deprecated-declarations])
gl_WARN_ADD([-fdiagnostics-show-option])
export WARN_CFLAGS

AC_CONFIG_SUBDIRS(lib)

AC_CONFIG_FILES([
  Makefile
  doc/Makefile
  doc/cyclo/Makefile
  doc/doxygen/Doxyfile
  doc/reference/Makefile
  examples/Makefile
  gl/Makefile
  gltests/Makefile
  po/Makefile.in
  src/Makefile
  tests/Makefile
])
AC_OUTPUT
