dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2002, 2003, 2004 Simon Josefsson.
#
# This file is part of GNU SASL.
#
# GNU SASL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# GNU SASL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU SASL; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

AC_INIT([gsasl], [0.2.3], [bug-gsasl@gnu.org])

AC_PREREQ(2.59)
AM_INIT_AUTOMAKE([1.9 gnits])
AC_CONFIG_HEADERS(config.h)
AB_INIT

# Internationalization.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.14.1)

# Checks for programs.
AC_PROG_CC
gl_EARLY
AC_PROG_LIBTOOL
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)

# Checks for header files.
AC_CHECK_HEADERS(sys/types.h sys/poll.h sys/time.h sys/select.h sys/socket.h)
AC_CHECK_HEADERS(unistd.h netdb.h netinet/in.h pwd.h errno.h)

# Checks for library functions.
AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)

# We want getaddrinfo, should be a gnulib module for it.
AC_CHECK_FUNCS(getaddrinfo)

# For gnulib stuff in gl/.
gl_SOURCE_BASE(gl)
gl_M4_BASE(gl/m4)
gl_LIB(libgl)
gl_MODULES(getopt progname strdup exit error getpass-gnu getaddrinfo iconvme)
gl_INIT

# Try to find readline.
AC_CHECK_HEADERS(readline/readline.h)
AC_CHECK_LIB(readline, readline)
AM_CONDITIONAL(READLINE, test "$ac_cv_lib_readline_readline" = "yes")

# Check for gtk-doc.
GTK_DOC_CHECK(1.1)

# Set up the library.
AC_CONFIG_SUBDIRS(lib)

# We are done.
AC_CONFIG_FILES(Makefile po/Makefile.in \
		doc/Makefile doc/reference/Makefile doc/doxygen/Doxyfile \
		gl/Makefile src/Makefile examples/Makefile tests/Makefile)
AC_OUTPUT
