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

if ENABLE_GTK_DOC
SUBDIRS = reference
endif

EXTRA_DIST = gdoc gdoc-error gsasl-example1.c \
	gsasl.html gsasl.ps gsasl.pdf texinfo.css \
	doxygen/Doxyfile.in doxygen/gdoc2doxygen

info_TEXINFOS = gsasl.texi
gsasl_TEXINFOS = gpl.texi fdl.texi $(gdoc_TEXINFOS) \
	gsasl-callback-password.texi gsasl-callback-authorization.texi \
	gsasl-callback-authentication.texi gsasl-callback-validate.texi \
	gsasl-callback-retrieve.texi gsasl-callback-cram-md5.texi \
	gsasl-callback-digest-md5.texi gsasl-callback-passcode.texi \
	gsasl-callback-gssapi.texi gsasl-callback-securid.texi \
	gsasl-callback-client-service.texi gsasl-callback-server-service.texi \
	gsasl-api-error-labels.texi

gsasl-api-error-labels.texi: $(top_srcdir)/lib/error.c
	$(PERL) $(srcdir)/gdoc-error $^ > $@

AM_MAKEINFOHTMLFLAGS = --no-split --number-sections --css-include=texinfo.css

dist_man_MANS = gsasl.1 $(gdoc_MANS)
MAINTAINERCLEANFILES = $(dist_man_MANS)

gsasl.1: $(top_srcdir)/src/gsasl.c $(top_srcdir)/src/gsasl.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="SASL library command line interface" \
		--output=$@ $(top_builddir)/src/gsasl

GDOC_SRC = $(top_srcdir)/lib/*.c
GDOC_TEXI_PREFIX = texi/
GDOC_MAN_PREFIX = man/
GDOC_MAN_EXTRA_ARGS = -module $(PACKAGE) -sourceversion $(VERSION) \
	-bugsto $(PACKAGE_BUGREPORT) -includefuncprefix -seeinfo $(PACKAGE) \
	-copyright "2002, 2003 Simon Josefsson" -verbatimcopying
include $(srcdir)/Makefile.gdoci
