## Process this file with automake to produce Makefile.in
# Copyright (C) 2002 Simon Josefsson.
#
# This file is part of Libgsasl.
#
# Libgsasl is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Libgsasl is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

lib_LTLIBRARIES = libgsasl.la

INCLUDES = -I../intl @LIBNTLM_CFLAGS@ @LIBGCRYPT_CFLAGS@ @GSSAPI_CFLAGS@ @LIBSTRINGPREP_CFLAGS@

include_HEADERS = gsasl.h

libgsasl_la_SOURCES = init.c done.c error.c version.c callback.c \
			supportp.c suggest.c listmech.c \
			hexdump.c base64.c md5pwd.c \
			xstart.c xstep.c xfinish.c xcode.c \
			common.c internal.h gettext.h \
			external.h external.c \
			anonymous.h anonymous.c \
			plain.h plain.c \
			login.h login.c \
			cram-md5.h cram-md5.c \
			digest-md5.h digest-md5.c \
			x-ntlm.h ntlm.c \
			x-gssapi.h gssapi.c \
			securid.h securid.c

libgsasl_la_LIBADD = @LIBINTL@ @LIBGCRYPT_LIBS@ @LIBNTLM_LIBS@ @GSSAPI_LIBS@ @LIBSTRINGPREP_LIBS@ -lm
libgsasl_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

localedir = $(datadir)/locale

DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

indent:
	indent $(libgsasl_la_SOURCES)
