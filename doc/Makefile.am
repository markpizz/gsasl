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

SUBDIRS = reference

EXTRA_DIST = gdoc gdoc-error gsasl-example1.c \
	gsasl.html gsasl.ps gsasl.pdf \
	$(gsasl_html_auto_deps) \
	doxygen/Doxyfile.in doxygen/gdoc2doxygen

#	gsasl-db.xml gsasl-db.txt gsasl-db.ps gsasl-db.pdf

info_TEXINFOS = gsasl.texi
ps_TEXINFOS = gsasl.texi
pdf_TEXINFOS = gsasl.texi
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

gsasl.html: gsasl.texi $(gsasl_TEXINFOS)
	$(MAKEINFO) --html --no-split --number-sections gsasl.texi

dist_man_MANS = gsasl.1 $(gdoc_MANS)
DISTCLEANFILES = $(dist_man_MANS)

gsasl.1: $(top_srcdir)/src/gsasl.c $(top_builddir)/src/gsasl
	$(HELP2MAN) \
		--name="SASL library command line interface" \
		--help-option="--program-name gsasl --help" \
		--output=$@ $(top_builddir)/src/gsasl

GDOC_SRC = $(top_srcdir)/lib/*.c
GDOC_TEXI_PREFIX = texi/
GDOC_MAN_PREFIX = man/
GDOC_MAN_EXTRA_ARGS = -module $(PACKAGE) -sourceversion $(VERSION) \
	-bugsto $(PACKAGE_BUGREPORT) -includefuncprefix -seeinfo $(PACKAGE) \
	-copyright "2002, 2003 Simon Josefsson" -verbatimcopying
include $(srcdir)/Makefile.gdoci

# DocBook

gsasl_html_auto_deps = html/a1563.html html/a1686.html			\
	html/c1176.html html/c1201.html html/c1211.html			\
	html/c1214.html html/c1219.html html/c1224.html			\
	html/c1229.html html/c1308.html html/c16.html html/c261.html	\
	html/c364.html html/c541.html html/c803.html html/c9.html	\
	html/c917.html html/i1313.html html/i1444.html html/index.html	\
	html/x1052.html html/x1099.html html/x1186.html			\
	html/x1191.html html/x1196.html html/x1272.html			\
	html/x1671.html html/x1789.html html/x179.html html/x195.html	\
	html/x214.html html/x232.html html/x29.html html/x297.html	\
	html/x300.html html/x319.html html/x345.html html/x376.html	\
	html/x45.html html/x456.html html/x490.html html/x553.html	\
	html/x558.html html/x611.html html/x625.html html/x740.html	\
	html/x815.html html/x835.html html/x842.html html/x929.html	\
	html/x976.html html/x988.html html/x995.html

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
