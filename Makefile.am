## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
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

SUBDIRS = po gl lib src examples gltests tests doc

EXTRA_DIST = cfg.mk maint.mk .clcopying

ACLOCAL_AMFLAGS = -I m4 -I gl/m4
DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --disable-obsolete

# Maintainer targets

ChangeLog:
	git log --pretty --numstat --summary | git2cl > ChangeLog
	cat .clcopying >> ChangeLog

htmldir = ../www-$(PACKAGE)
tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`

release:
	cd lib && make release
	! git-tag -l $(tag) | grep $(PACKAGE) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	git commit -m Generated. ChangeLog
	git-tag -u b565716f! -m $(VERSION) $(tag)
	cd doc && env MAKEINFO="makeinfo -I ../examples" \
		      TEXI2DVI="texi2dvi -I ../examples" \
		../build-aux/gendocs.sh --html "--css-include=texinfo.css" \
		-o ../$(htmldir)/manual/ $(PACKAGE) "GNU SASL"
	cp -v doc/reference/html/*.html doc/reference/html/*.png doc/reference/html/*.devhelp doc/reference/html/*.css $(htmldir)/reference/
	cd doc/doxygen && doxygen && cd ../.. && cp -v doc/doxygen/html/* $(htmldir)/doxygen/ && cd doc/doxygen/latex && make refman.pdf && cd ../../../ && cp doc/doxygen/latex/refman.pdf $(htmldir)/doxygen/$(PACKAGE).pdf
	git-push
	git-push --tags
	gnupload --to alpha.gnu.org:gsasl $(distdir).tar.gz
	cd $(htmldir) && cvs commit -m "Update." manual/ reference/ doxygen/
