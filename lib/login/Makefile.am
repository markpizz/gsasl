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

AM_CPPFLAGS = -I$(srcdir)/../src -I$(builddir)/../src

noinst_LTLIBRARIES = libgsasl-login.la
libgsasl_login_la_SOURCES = login.h login.c

indent:
	indent $(libgsasl_login_la_SOURCES)
