## Process this file with automake to produce Makefile.in
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

noinst_DATA = cram-md5.pwd

AM_CPPFLAGS = -I$(top_builddir)/lib/src -I$(srcdir)/../gl -I../gl
AM_LDFLAGS = -no-install
LDADD = ../lib/src/libgsasl.la libutils.la

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

TESTS_ENVIRONMENT = THREADSAFETY_FILES=$(top_srcdir)/lib/*/*.c

TESTS = simple cram-md5 digest-md5 md5file threadsafety \
	old-cram-md5
check_PROGRAMS = simple cram-md5 digest-md5 md5file \
	old-cram-md5
dist_check_SCRIPTS = threadsafety
