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

DEFS = -DLOCALEDIR=\"$(datadir)/locale\" @DEFS@
INCLUDES = @LIBNTLM_CFLAGS@ @LIBGCRYPT_CFLAGS@ @LIBNTLM_CFLAGS@ \
	@GSSAPI_CFLAGS@ @GSS_CFLAGS@ @SHISHI_CFLAGS@

include_HEADERS = gsasl.h

libgsasl_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
libgsasl_la_LIBADD = @LTLIBINTL@ @LIBGCRYPT_LIBS@ @LIBNTLM_LIBS@ \
	@GSSAPI_LIBS@ @GSS_LIBS@ @SHISHI_LIBS@
libgsasl_la_SOURCES = gsasl.h.in internal.h gettext.h \
	init.c done.c error.c version.c callback.c common.c \
	supportp.c suggest.c listmech.c \
	xstart.c xstep.c xfinish.c xcode.c \
	hexdump.c base64.c md5pwd.c

if STRINGPREP
libgsasl_la_SOURCES += stringprep.c
else
libgsasl_la_SOURCES += stringprep-no.c
endif

if CLIENT
libgsasl_la_SOURCES += callback-c.c
endif

if SERVER
libgsasl_la_SOURCES += callback-s.c
endif

# Plugins:

if EXTERNAL
libgsasl_la_SOURCES += external.h external.c
endif

if ANONYMOUS
libgsasl_la_SOURCES += anonymous.h anonymous.c
endif

if PLAIN
libgsasl_la_SOURCES += plain.h plain.c
endif

if LOGIN
libgsasl_la_SOURCES += login.h login.c
endif

if CRAM_MD5
libgsasl_la_SOURCES += cram-md5.h cram-md5.c
endif

if DIGEST_MD5
libgsasl_la_SOURCES += digest-md5.h digest-md5.c
endif

if NTLM
libgsasl_la_SOURCES += x-ntlm.h ntlm.c
endif

if GSSAPI
libgsasl_la_SOURCES += x-gssapi.h gssapi.c
endif			

if SECURID
libgsasl_la_SOURCES += securid.h securid.c
endif			

if KERBEROS_V5
libgsasl_la_SOURCES += kerberos_v5.h kerberos_v5.c
endif

indent:
	indent $(libgsasl_la_SOURCES)
