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
AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl \
	-I$(top_srcdir)/lib/src -I$(top_builddir)/lib/src \
	$(LASSO_CFLAGS)
AM_LDFLAGS = -no-install
LDADD = $(top_builddir)/lib/src/libgsasl.la $(top_builddir)/gl/libgl.la \
	$(LASSO_LIBS)

EXTRA_DIST = README
EXTRA_DIST += gsasl-saml20-sp.php
EXTRA_DIST += sp-metadata.xml sp-key.pem sp-crt.pem
EXTRA_DIST += openidp.feide.no/idp-metadata.xml
EXTRA_DIST += idp.protectnetwork.org/idp-metadata.xml

if LASSO
noinst_PROGRAMS = smtp-server-saml20 gsasl-saml20-request
endif
