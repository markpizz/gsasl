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

AM_CPPFLAGS = -I$(top_srcdir)/gl -I../lib/src -I$(top_srcdir)/lib/src

bin_PROGRAMS = gsasl

BUILT_SOURCES = gsasl_cmd.c gsasl_cmd.h
gsasl_SOURCES = gsasl.c $(BUILT_SOURCES) gsasl.ggo \
	imap.c imap.h smtp.c smtp.h \
	callbacks.h callbacks.c internal.h
gsasl_LDADD = ../lib/src/libgsasl.la ../gl/libgl.la

localedir = $(datadir)/locale

DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

$(BUILT_SOURCES): gsasl.ggo
	gengetopt --input gsasl.ggo --file-name gsasl_cmd
