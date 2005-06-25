## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005 Simon Josefsson.
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
# along with GNU SASL; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

dist_noinst_DATA = cram-md5.pwd

AM_CPPFLAGS = -I$(top_srcdir)/lib/src -I$(top_builddir)/lib/src \
	-I$(srcdir)/../gl -I../gl
AM_LDFLAGS = -no-install
LDADD = ../lib/src/libgsasl.la libutils.la

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

TESTS_ENVIRONMENT = SHISHI_KEYS=$(srcdir)/gssapi.key \
	SHISHI_TICKETS=$(srcdir)/gssapi.tkt \
	SHISHI_CONFIG=ignore-this-warning \
	SHISHI_HOME=ignore-this-warning \
	SHISHI_USER=ignore-this-warning \
	THREADSAFETY_FILES=$(top_srcdir)/lib/*/*.c \
	MD5FILE=$(srcdir)/cram-md5.pwd

ctests = external cram-md5 digest-md5 md5file

if OBSOLETE
ctests += simple old-md5file old-cram-md5 old-digest-md5
endif

# old-gssapi

TESTS = threadsafety $(ctests)	
check_PROGRAMS = $(ctests)
dist_check_SCRIPTS = threadsafety
