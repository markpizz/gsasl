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

SUBDIRS = reference man

gsasl_texi_auto_deps = gsasl-api-version.texi gsasl-api-global.texi \
	gsasl-api-session.texi gsasl-api-callback.texi gsasl-api-utils.texi \
	gsasl-api-error.texi gsasl-api-error-labels.texi

# gsasl.xml gsasl-db.txt gsasl-db.html gsasl-db.ps gsasl-db.pdf

EXTRA_DIST = gdoc gdoc-error gsasl-example1.c \
	gsasl.html gsasl.ps gsasl.pdf $(gsasl_texi_auto_deps) \
	doxygen/Doxyfile.in doxygen/gdoc2doxygen

info_TEXINFOS = gsasl.texi
ps_TEXINFOS = gsasl.texi
pdf_TEXINFOS = gsasl.texi
gsasl_TEXINFOS = gpl.texi fdl.texi $(gsasl_texi_auto_deps) \
	gsasl-callback-password.texi gsasl-callback-authorization.texi \
	gsasl-callback-authentication.texi gsasl-callback-validate.texi \
	gsasl-callback-retrieve.texi gsasl-callback-cram-md5.texi \
	gsasl-callback-digest-md5.texi gsasl-callback-passcode.texi \
	gsasl-callback-gssapi.texi gsasl-callback-securid.texi \
	gsasl-callback-client-service.texi gsasl-callback-server-service.texi

gsasl_api_version_deps = $(top_srcdir)/lib/version.c

gsasl_api_global_deps = $(top_srcdir)/lib/init.c \
			$(top_srcdir)/lib/done.c \
			$(top_srcdir)/lib/listmech.c \
			$(top_srcdir)/lib/supportp.c \
			$(top_srcdir)/lib/suggest.c

gsasl_api_callback_deps = $(top_srcdir)/lib/callback.c \
			$(top_srcdir)/lib/callback-s.c \
			$(top_srcdir)/lib/callback-c.c

gsasl_api_session_deps = $(top_srcdir)/lib/xstart.c \
			$(top_srcdir)/lib/xstep.c \
			$(top_srcdir)/lib/xfinish.c \
			$(top_srcdir)/lib/xcode.c

gsasl_api_utils_deps = $(top_srcdir)/lib/stringprep.c \
			$(top_srcdir)/lib/base64.c \
			$(top_srcdir)/lib/hexdump.c \
			$(top_srcdir)/lib/md5pwd.c

gsasl_api_error_deps = $(top_srcdir)/lib/error.c

gsasl_api_error_label_deps = $(gsasl_api_error_deps)

gsasl-api-global.texi: $(gsasl_api_global_deps)
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gsasl-api-version.texi: $(gsasl_api_version_deps)
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gsasl-api-session.texi: $(gsasl_api_session_deps)
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gsasl-api-callback.texi: $(gsasl_api_callback_deps)
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gsasl-api-utils.texi: $(gsasl_api_utils_deps)
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gsasl-api-error.texi: $(gsasl_api_error_deps)
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gsasl-api-error-labels.texi: $(gsasl_api_error_label_deps)
	$(PERL) $(srcdir)/gdoc-error $^ > $@

gsasl.html: gsasl.texi
	$(MAKEINFO) --html --no-split --number-sections $<
#	$(TEXI2HTML) -nosec_nav $<

# Docbook:

gsasl.xml: gsasl.texi
	$(MAKEINFO) --docbook $<

gsasl-db.txt: gsasl.xml
	mkdir db.tmp && \
	cp $< db.tmp && \
	cd db.tmp && \
	$(DOCBOOK2TXT) --nochunks $< && \
	cd .. && \
	mv db.tmp/gsasl.txt gsasl-db.txt && \
	rm -rf db.tmp

gsasl-db.html: gsasl.xml
	mkdir db.tmp && \
	cp $< db.tmp && \
	cd db.tmp && \
	$(DOCBOOK2HTML) --nochunks $< && \
	cd .. && \
	mv db.tmp/gsasl.html gsasl-db.html && \
	rm -rf db.tmp

gsasl-db.ps: gsasl.xml
	mkdir db.tmp && \
	cp $< db.tmp && \
	cd db.tmp && \
	$(DOCBOOK2PS) $< && \
	cd .. && \
	mv db.tmp/gsasl.ps gsasl-db.ps && \
	rm -rf db.tmp

gsasl-db.pdf: gsasl.xml
	mkdir db.tmp && \
	cp $< db.tmp && \
	cd db.tmp && \
	$(DOCBOOK2PDF) $< && \
	cd .. && \
	mv db.tmp/gsasl.pdf gsasl-db.pdf && \
	rm -rf db.tmp
