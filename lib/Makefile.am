## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003 Simon Josefsson.
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

AM_CPPFLAGS = @LIBGCRYPT_CFLAGS@ @NETTLE_CFLAGS@
DEFS = -DLOCALEDIR=\"$(datadir)/locale\" @DEFS@

include_HEADERS = gsasl.h

libgsasl_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
libgsasl_la_LIBADD = @LTLIBINTL@ @LIBGCRYPT_LIBS@ @NETTLE_LIBS@
libgsasl_la_SOURCES = gsasl.h.in internal.h gettext.h \
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

if EXTERNAL
libgsasl_la_SOURCES += external/external.h external/external.c
endif

if ANONYMOUS
libgsasl_la_SOURCES += anonymous/anonymous.h anonymous/anonymous.c
endif

if PLAIN
libgsasl_la_SOURCES += plain/plain.h plain/plain.c
endif

if LOGIN
libgsasl_la_SOURCES += login/login.h login/login.c
endif

if CRAM_MD5
libgsasl_la_SOURCES += cram-md5/cram-md5.h cram-md5/cram-md5.c
endif

if DIGEST_MD5
libgsasl_la_SOURCES += digest-md5/digest-md5.h digest-md5/digest-md5.c
endif

if NTLM
libgsasl_la_SOURCES += ntlm/x-ntlm.h ntlm/ntlm.c
endif

if GSSAPI
libgsasl_la_SOURCES += gssapi/x-gssapi.h gssapi/gssapi.c
endif			

if SECURID
libgsasl_la_SOURCES += securid/securid.h securid/securid.c
endif			

if KERBEROS_V5
libgsasl_la_SOURCES += kerberos_v5/kerberos_v5.h kerberos_v5/kerberos_v5.c
endif

indent:
	indent $(am__libgsasl_la_SOURCES_DIST)
