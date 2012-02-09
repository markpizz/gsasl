# Copyright (C) 2006-2012 Simon Josefsson
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

WFLAGS ?= --enable-gcc-warnings
ADDFLAGS ?=
CFGFLAGS ?= --enable-gtk-doc --enable-gtk-doc-pdf $(ADDFLAGS) $(WFLAGS)

_build-aux = lib/build-aux

INDENT_SOURCES = `find . -name '*.[chly]' | grep -v -e /gl -e build-aux -e /win32/ -e /examples/`

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
.DEFAULT_GOAL := bootstrap
endif

local-checks-to-skip = sc_prohibit_strcmp sc_error_message_uppercase	\
	sc_prohibit_have_config_h sc_require_config_h			\
	sc_require_config_h_first sc_immutable_NEWS sc_po_check
VC_LIST_ALWAYS_EXCLUDE_REGEX = \
	^((lib/)?GNUmakefile|gtk-doc.make|m4/pkg.m4|doc/gendocs_template|doc/fdl-1.3.texi|doc/specification|doc/doxygen/Doxyfile|(lib/)?po/.*.po.in|(lib/)?maint.mk|((lib/)?(gl|gltests|build-aux))/.*)

# Explicit syntax-check exceptions.
exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = ^doc/.*\.(dia|png)|tests/gssapi.tkt$$
exclude_file_name_regexp--sc_GPL_version = ^doc/lgpl-2.1.texi|lib/.*$$
exclude_file_name_regexp--sc_copyright_check = ^doc/gsasl.texi$$
exclude_file_name_regexp--sc_unmarked_diagnostics = ^examples/.*|src/gsasl.c$$
exclude_file_name_regexp--sc_bindtextdomain = ^doc/print-errors.c|examples/.*|lib/digest-md5/test-parser.c|lib/tests/test-error.c|tests/.*$$
exclude_file_name_regexp--sc_program_name = $(exclude_file_name_regexp--sc_bindtextdomain)
exclude_file_name_regexp--sc_prohibit_magic_number_exit = ^doc/gsasl.texi|tests.*$$
exclude_file_name_regexp--sc_trailing_blank = ^doc/.*\.(eps|png)|(lib/)?po/.*$$

update-copyright-env = UPDATE_COPYRIGHT_HOLDER="Simon Josefsson" UPDATE_COPYRIGHT_USE_INTERVALS=2

autoreconf:
	for f in po/*.po.in lib/po/*.po.in; do \
		cp $$f `echo $$f | sed 's/.in//'`; \
	done
	mv $(_build-aux)/config.rpath $(_build-aux)/config.rpath-
	touch ChangeLog lib/ChangeLog
	test -f ./configure || autoreconf --install
	mv $(_build-aux)/config.rpath- $(_build-aux)/config.rpath

update-po:
	$(MAKE) -C lib refresh-po PACKAGE=libgsasl
	$(MAKE) refresh-po PACKAGE=gsasl
	for f in `ls lib/po/*.po po/*.po | grep -v quot.po`; do \
		cp $$f $$f.in; \
	done
	git add po/*.po.in lib/po/*.po.in
	git commit -m "Sync with TP." \
		po/LINGUAS po/*.po.in lib/po/LINGUAS lib/po/*.po.in

bootstrap: autoreconf
	./configure $(CFGFLAGS)

glimport:
	gnulib-tool --m4-base gl/m4 --add-import
	cd lib && gnulib-tool --m4-base gl/m4 --add-import

review-diff:
	git diff `git describe --abbrev=0`.. \
	| grep -v -e ^index -e '^diff --git' \
	| filterdiff -p 1 -x 'gl/*' -x 'gltests/*' -x 'lib/build-aux/*' -x 'lib/gl*' -x 'lib/gltests/*' -x 'po/*' -x 'lib/po/*' -x 'maint.mk' -x 'lib/maint.mk' -x '.gitignore' -x '.x-sc*' -x ChangeLog -x GNUmakefile \
	| less

# Release

htmldir = ../www-$(PACKAGE)

i18n:
	-$(MAKE) update-po

coverage-my:
	ln -s . gl/unistr/unistr
	ln -s . gltests/glthread/glthread
	ln -s . gltests/unistr/unistr
	$(MAKE) coverage WERROR_CFLAGS= VALGRIND=

coverage-copy:
	rm -fv `find $(htmldir)/coverage -type f | grep -v CVS`
	mkdir -p $(htmldir)/coverage/
	cp -rv $(COVERAGE_OUT)/* $(htmldir)/coverage/

coverage-upload:
	cd $(htmldir) && \
	find coverage -type d -! -name CVS -! -name '.' \
		-exec cvs add {} \; && \
	find coverage -type d -! -name CVS -! -name '.' \
		-exec sh -c "cvs add -kb {}/*.png" \; && \
	find coverage -type d -! -name CVS -! -name '.' \
		-exec sh -c "cvs add {}/*.html" \; && \
	cvs add coverage/$(PACKAGE).info coverage/gcov.css || true && \
	cvs commit -m "Update." coverage

clang:
	make clean
	scan-build ./configure
	rm -rf scan.tmp
	scan-build -o scan.tmp make

clang-copy:
	rm -fv `find $(htmldir)/clang-analyzer -type f | grep -v CVS`
	mkdir -p $(htmldir)/clang-analyzer/
	cp -rv scan.tmp/*/* $(htmldir)/clang-analyzer/

clang-upload:
	cd $(htmldir) && \
		cvs add clang-analyzer || true && \
		cvs add clang-analyzer/*.css clang-analyzer/*.js \
			clang-analyzer/*.html || true && \
		cvs commit -m "Update." clang-analyzer

cyclo-copy:
	cp -v doc/cyclo/cyclo-$(PACKAGE).html $(htmldir)/cyclo/index.html

cyclo-upload:
	cd $(htmldir) && cvs commit -m "Update." cyclo/index.html

gendoc-copy:
	cd doc && env MAKEINFO="makeinfo -I ../examples" \
		      TEXI2DVI="texi2dvi -I ../examples" \
		$(SHELL) ../$(_build-aux)/gendocs.sh \
			--html "--css-include=texinfo.css" \
			-o ../$(htmldir)/manual/ $(PACKAGE) "$(PACKAGE_NAME)"

gendoc-upload:
	cd $(htmldir) && \
		cvs add manual || true && \
		cvs add manual/html_node || true && \
		cvs add -kb manual/*.gz manual/*.pdf || true && \
		cvs add manual/*.txt manual/*.html \
			manual/html_node/*.html || true && \
		cvs commit -m "Update." manual/

gtkdoc-copy:
	mkdir -p $(htmldir)/reference/
	cp -v doc/reference/$(PACKAGE).pdf \
		doc/reference/html/*.html \
		doc/reference/html/*.png \
		doc/reference/html/*.devhelp \
		doc/reference/html/*.css \
		$(htmldir)/reference/

gtkdoc-upload:
	cd $(htmldir) && \
		cvs add reference || true && \
		cvs add -kb reference/*.png reference/*.pdf || true && \
		cvs add reference/*.html reference/*.css \
			reference/*.devhelp || true && \
		cvs commit -m "Update." reference/

doxygen-copy:
	cd doc/doxygen && \
		doxygen && \
		cd ../.. && \
		cp -v doc/doxygen/html/* $(htmldir)/doxygen/ && \
		cd doc/doxygen/latex && \
		make refman.pdf && \
		cd ../../../ && \
		cp doc/doxygen/latex/refman.pdf $(htmldir)/doxygen/$(PACKAGE).pdf

doxygen-upload:
	cd $(htmldir) && \
		cvs commit -m "Update." doxygen/

ChangeLog:
	git2cl > ChangeLog
	cat .clcopying >> ChangeLog

tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`

tarball:
	$(MAKE) -C lib tarball
	! git tag -l $(tag) | grep $(PACKAGE) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck

binaries:
	-mkdir windows/dist
	cp $(distdir).tar.gz windows/dist
	cd windows && $(MAKE) -f gsasl4win.mk gsasl4win VERSION=$(VERSION)

source:
	git tag -u b565716f! -m $(VERSION) $(tag)

release-check: syntax-check i18n tarball binaries cyclo-copy gendoc-copy gtkdoc-copy doxygen-copy coverage-my coverage-copy clang clang-copy

release-upload-www: cyclo-upload gendoc-upload gtkdoc-upload doxygen-upload coverage-upload clang-upload

release-upload-ftp:
	gnupload --to alpha.gnu.org:$(PACKAGE) $(distdir).tar.gz lib/lib$(distdir).tar.gz windows/gsasl-*.zip
	cp -v $(distdir).tar.gz* lib/lib$(distdir).tar.gz* windows/gsasl-*.zip* ../releases/$(PACKAGE)/
	git push
	git push --tags

release: release-check release-upload-www source release-upload-ftp
