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

if ENABLE_GTK_DOC
SUBDIRS = reference
endif

EXTRA_DIST = gdoc gdoc-error gsasl-example1.c \
	gsasl.html gsasl.ps gsasl.pdf \
	gsasl-db.xml gsasl-db.txt gsasl-db.ps gsasl-db.pdf \
	$(gsasl_html_auto_deps) \
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

AM_MAKEINFOHTMLFLAGS = --no-split --number-sections

dist_man_MANS = gsasl.1 $(gdoc_MANS)
DISTCLEANFILES = $(dist_man_MANS)

gsasl.1: $(top_srcdir)/src/gsasl.c $(top_builddir)/src/gsasl
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

# DocBook

gsasl_html_auto_deps = html/a2496.html html/a2612.html html/c1101.html	\
	html/c1189.html html/c14.html html/c1704.html html/c1837.html	\
	html/c1990.html html/c2197.html html/c2440.html			\
	html/c2450.html html/c2455.html html/c2465.html			\
	html/c2468.html html/c2474.html html/c2479.html			\
	html/c2483.html html/c2487.html html/c2492.html html/c303.html	\
	html/c393.html html/c427.html html/c8.html html/i2706.html	\
	html/i2838.html html/index.html html/x1028.html html/x177.html	\
	html/x193.html html/x24.html html/x2429.html html/x256.html	\
	html/x2681.html html/x274.html html/x317.html html/x329.html	\
	html/x347.html html/x374.html html/x448.html html/x46.html	\
	html/x482.html html/x57.html html/x571.html html/x645.html	\
	html/x720.html html/x836.html html/x872.html html/x948.html

gsasl-db.xml: gsasl.texi $(gsasl_TEXINFOS)
	$(MAKEINFO) --docbook --output $@ gsasl.texi

$(gsasl_html_auto_deps): gsasl-db.xml
	$(DOCBOOK2HTML) -o html $^

gsasl-db.txt: gsasl-db.xml
	$(DOCBOOK2TXT) $^

gsasl-db.pdf: gsasl-db.xml
	$(DOCBOOK2PDF) $^

gsasl-db.ps: gsasl-db.xml
	$(DOCBOOK2PS) $^
