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

INCLUDES = -I../lib -I../argp -I../intl @LIBSTRINGPREP_CFLAGS@

bin_PROGRAMS = gsasl

gsasl_SOURCES = gsasl.c callbacks.h callbacks.c gettext.h
gsasl_LDADD = ../lib/libgsasl.la @LIBINTL@ @LIBARGP@ @LIBSTRINGPREP_LIBS@

indent:
	indent $(gsasl_SOURCES)
