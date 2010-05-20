# Copyright (C) 2006, 2007, 2008, 2009, 2010 Simon Josefsson
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

build_aux = lib/build-aux

INDENT_SOURCES = `find . -name \*.c -or -name \*.h | grep -v -e /gl -e build-aux -e /win32/`

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
.DEFAULT_GOAL := bootstrap
endif

local-checks-to-skip = sc_prohibit_strcmp sc_error_message_uppercase	\
	sc_prohibit_have_config_h sc_require_config_h			\
	sc_require_config_h_first sc_unmarked_diagnostics		\
	sc_GPL_version sc_immutable_NEWS sc_copyright_check
VC_LIST_ALWAYS_EXCLUDE_REGEX = ^((lib/)?(gl|gltests|build-aux))/.*

autoreconf:
	for f in po/*.po.in lib/po/*.po.in; do \
		cp $$f `echo $$f | sed 's/.in//'`; \
	done
	mv $(build_aux)/config.rpath $(build_aux)/config.rpath-
	test -f ./configure || autoreconf --install
	mv $(build_aux)/config.rpath- $(build_aux)/config.rpath

update-po:
	$(MAKE) -C lib refresh-po PACKAGE=libgsasl
	$(MAKE) refresh-po PACKAGE=gsasl
	for f in `ls lib/po/*.po po/*.po | grep -v quot.po`; do \
		cp $$f $$f.in; \
	done
	git add {lib/,}po/*.po.in
	git commit -m "Sync with TP." {lib/,}po/LINGUAS {lib/,}po/*.po.in

bootstrap: autoreconf
	./configure $(CFGFLAGS)

glimport:
	gnulib-tool --m4-base gl/m4 --import
	cd lib && gnulib-tool --m4-base gl/m4 --import

web-coverage:
	rm -fv `find $(htmldir)/coverage -type f | grep -v CVS`
	cp -rv doc/coverage/* $(htmldir)/coverage/

upload-web-coverage:
	cd $(htmldir) && \
		cvs commit -m "Update." coverage

W32ROOT ?= $(HOME)/gnutls4win/inst

mingw32: autoreconf
	./configure $(CFGFLAGS) --host=i586-mingw32msvc --build=`$(build_aux)/config.guess` --prefix=$(W32ROOT)

ChangeLog:
	git2cl > ChangeLog
	cat .clcopying >> ChangeLog

htmldir = ../www-$(PACKAGE)
tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`

release: prepare upload web upload-web

prepare:
	cd lib && make prepare
	! git tag -l $(tag) | grep $(PACKAGE) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	git commit -m Generated. ChangeLog
	git tag -u b565716f! -m $(VERSION) $(tag)

upload:
	cd lib && make upload
	git push
	git push --tags
	gnupload --to alpha.gnu.org:$(PACKAGE) $(distdir).tar.gz
	cp $(distdir).tar.gz $(distdir).tar.gz.sig ../releases/$(PACKAGE)/

web:
	cd doc && env MAKEINFO="makeinfo -I ../examples" \
		      TEXI2DVI="texi2dvi -I ../examples" \
		../$(build_aux)/gendocs.sh --html "--css-include=texinfo.css" \
		-o ../$(htmldir)/manual/ $(PACKAGE) "$(PACKAGE_NAME)"
	cd doc/doxygen && doxygen && cd ../.. && cp -v doc/doxygen/html/* $(htmldir)/doxygen/ && cd doc/doxygen/latex && make refman.pdf && cd ../../../ && cp doc/doxygen/latex/refman.pdf $(htmldir)/doxygen/$(PACKAGE).pdf
	cp -v doc/reference/html/*.html doc/reference/html/*.png doc/reference/html/*.devhelp doc/reference/html/*.css $(htmldir)/reference/
	cp -v doc/cyclo/cyclo-$(PACKAGE).html $(htmldir)/cyclo/

upload-web:
	cd $(htmldir) && \
		cvs commit -m "Update." manual/ reference/ doxygen/ cyclo/

review-diff:
	git diff `git describe --abbrev=0`.. \
	| grep -v -e ^index -e '^diff --git' \
	| filterdiff -p 1 -x 'gl/*' -x 'gltests/*' -x 'lib/build-aux/*' -x 'lib/gl*' -x 'lib/gltests/*' -x 'po/*' -x 'lib/po/*' -x 'maint.mk' -x 'lib/maint.mk' -x '.gitignore' -x '.x-sc*' -x ChangeLog -x GNUmakefile \
	| less
