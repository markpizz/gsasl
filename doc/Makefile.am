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

gsasl_html_auto_deps = html/a2446.html html/a2562.html html/c1103.html	\
	html/c1191.html html/c16.html html/c1706.html html/c1839.html	\
	html/c2046.html html/c2147.html html/c2390.html			\
	html/c2400.html html/c2405.html html/c2415.html			\
	html/c2418.html html/c2424.html html/c2429.html			\
	html/c2433.html html/c2437.html html/c2442.html html/c305.html	\
	html/c395.html html/c429.html html/c9.html html/i2656.html	\
	html/i2788.html html/index.html html/x1030.html html/x179.html	\
	html/x195.html html/x2379.html html/x258.html html/x26.html	\
	html/x2631.html html/x276.html html/x319.html html/x331.html	\
	html/x349.html html/x376.html html/x450.html html/x48.html	\
	html/x484.html html/x573.html html/x59.html html/x647.html	\
	html/x722.html html/x838.html html/x874.html html/x950.html

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
