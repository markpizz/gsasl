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

lib_LTLIBRARIES = libgsasl.la

AM_CPPFLAGS = -I$(top_srcdir)/gl @LIBGCRYPT_CFLAGS@ @NETTLE_CFLAGS@
DEFS = -DLOCALEDIR=\"$(datadir)/locale\" @DEFS@

include_HEADERS = gsasl.h

libgsasl_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
libgsasl_la_LIBADD = @LTLIBINTL@ @LIBGCRYPT_LIBS@ @NETTLE_LIBS@
libgsasl_la_SOURCES = gsasl.h.in internal.h crypto.h \
	init.c done.c error.c version.c common.c \
	callback.c callback-c.c callback-s.c \
	supportp.c suggest.c listmech.c \
	xstart.c xstep.c xfinish.c xcode.c \
	base64.c md5pwd.c obsolete.c

if NETTLE
libgsasl_la_SOURCES += nettle.c
endif
if LIBGCRYPT
libgsasl_la_SOURCES += libgcrypt.c
endif

if STRINGPREP
libgsasl_la_SOURCES += stringprep.c
else
libgsasl_la_SOURCES += stringprep-no.c
endif

# Plugins:

SUBDIRS =

if EXTERNAL
SUBDIRS += external
libgsasl_la_LIBADD += external/libgsasl-external.la
endif

if ANONYMOUS
SUBDIRS += anonymous
libgsasl_la_LIBADD += anonymous/libgsasl-anonymous.la
endif

if PLAIN
SUBDIRS += plain
libgsasl_la_LIBADD += plain/libgsasl-plain.la
endif

if LOGIN
SUBDIRS += login
libgsasl_la_LIBADD += login/libgsasl-login.la
endif

if CRAM_MD5
SUBDIRS += cram-md5
libgsasl_la_LIBADD += cram-md5/libgsasl-cram_md5.la
endif

if DIGEST_MD5
SUBDIRS += digest-md5
libgsasl_la_LIBADD += digest-md5/libgsasl-digest_md5.la
endif

if NTLM
SUBDIRS += ntlm
libgsasl_la_SOURCES += ntlm/x-ntlm.h ntlm/ntlm.c
endif

if GSSAPI
SUBDIRS += gssapi
libgsasl_la_LIBADD += gssapi/libgsasl-gssapi.la
endif			

if SECURID
SUBDIRS += securid
libgsasl_la_LIBADD += securid/libgsasl-securid.la
endif			

if KERBEROS_V5
SUBDIRS += kerberos_v5
libgsasl_la_LIBADD += kerberos_v5/libgsasl-kerberos_v5.la
endif

indent:
	indent $(am__libgsasl_la_SOURCES_DIST)
