## Process this file with automake to produce Makefile.in
# Copyright (C) 2002-2012 Simon Josefsson
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

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl \
	 -I$(top_srcdir)/lib/src -I$(top_builddir)/lib/src
AM_LDFLAGS = -no-install
LDADD = ../lib/src/libgsasl.la ../gl/libgl.la libutils.la

EXTRA_DIST = libgsasl.supp gssapi.key gssapi.tkt shishi.conf

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

TESTS_ENVIRONMENT = \
	SHISHI_KEYS=$(srcdir)/gssapi.key \
	SHISHI_TICKETS=$(srcdir)/gssapi.tkt \
	SHISHI_CONFIG=$(srcdir)/shishi.conf \
	SHISHI_HOME=$(srcdir) \
	SHISHI_USER=ignore-this-warning \
	THREADSAFETY_FILES=`ls $(top_srcdir)/lib/*/*.c | $(GREP) -v -e lib/gl/vasnprintf.c -e lib/gl/getdelim.c` \
	MD5FILE=$(srcdir)/cram-md5.pwd \
	EGREP="$(EGREP)" \
	GNUGSS=`if grep 'HAVE_LIBGSS 1' ../lib/config.h > /dev/null; then echo yes; else echo no; fi` \
	$(VALGRIND)

ctests = external cram-md5 digest-md5 md5file name errors suggest	\
	simple crypto scram scramplus symbols readnz gssapi gs2-krb5 saml20
if OBSOLETE
ctests += old-simple old-md5file old-cram-md5 old-digest-md5	\
	old-base64
endif

# old-gssapi

TESTS = threadsafety $(ctests)
check_PROGRAMS = $(ctests)
dist_check_SCRIPTS = threadsafety
