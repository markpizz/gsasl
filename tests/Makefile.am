## Process this file with automake to produce Makefile.in
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

dist_noinst_DATA = cram-md5.pwd

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl \
	 -I$(top_srcdir)/lib/src -I$(top_builddir)/lib/src
AM_LDFLAGS = -no-install
LDADD = ../lib/src/libgsasl.la ../gl/libgl.la libutils.la

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

TESTS_ENVIRONMENT = SHISHI_KEYS=$(srcdir)/gssapi.key \
	SHISHI_TICKETS=$(srcdir)/gssapi.tkt \
	SHISHI_CONFIG=ignore-this-warning \
	SHISHI_HOME=ignore-this-warning \
	SHISHI_USER=ignore-this-warning \
	THREADSAFETY_FILES=`ls $(top_srcdir)/lib/*/*.c | grep -v -e lib/gl/vasnprintf.c -e lib/gl/getdelim.c` \
	MD5FILE=$(srcdir)/cram-md5.pwd \
	$(VALGRIND)

ctests = external$(EXEEXT) cram-md5$(EXEEXT) digest-md5$(EXEEXT)	\
	md5file$(EXEEXT) name$(EXEEXT) errors$(EXEEXT)

if OBSOLETE
ctests += simple$(EXEEXT) old-md5file$(EXEEXT) old-cram-md5$(EXEEXT)	\
	old-digest-md5$(EXEEXT) old-base64$(EXEEXT)
endif

# old-gssapi

TESTS = threadsafety $(ctests)	
check_PROGRAMS = $(ctests)
dist_check_SCRIPTS = threadsafety
