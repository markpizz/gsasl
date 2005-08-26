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

AM_CPPFLAGS = -I$(top_srcdir)/gl -I../lib/src -I$(top_srcdir)/lib/src

bin_PROGRAMS = gsasl

BUILT_SOURCES = gsasl_cmd.c gsasl_cmd.h
gsasl_SOURCES = gsasl.c $(BUILT_SOURCES) gsasl.ggo \
	imap.c imap.h smtp.c smtp.h \
	callbacks.h callbacks.c internal.h
gsasl_LDADD = ../lib/src/libgsasl.la ../gl/libgl.la \
	@LTLIBREADLINE@ @LTLIBGNUTLS@

localedir = $(datadir)/locale

DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

$(BUILT_SOURCES): gsasl.ggo
	gengetopt --unamed-opts="HOST [PORT]" --input $< --file-name gsasl_cmd
