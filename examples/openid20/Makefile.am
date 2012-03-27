## Process this file with automake to produce Makefile.in
# Copyright (C) 2012 Simon Josefsson
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

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/lib/src -I$(top_builddir)/lib/src
LDADD = $(top_builddir)/lib/src/libgsasl.la

EXTRA_DIST = README gsasl-openid20-redirect.php gsasl-openid20-rp.php

noinst_PROGRAMS = smtp-server-openid20
