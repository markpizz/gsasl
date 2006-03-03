## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006 Simon Josefsson.
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
# along with GNU SASL; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

SUBDIRS = po gl lib src examples tests doc

ACLOCAL_AMFLAGS = -I m4 -I gl/m4
DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --disable-obsolete

# Maintainer targets

update-po: refresh-po
	cvs add `ls po/*.po | grep -v quot.po` || true && \
	cvs commit -m "Sync with TP." po/LINGUAS `ls po/*.po | grep -v quot.po`
	$(MAKE) -C lib update-po

ChangeLog:
	cvs2cl --fsf --FSF --usermap .cvsusers -I ChangeLog -I .cvs \
		-I autogen.sh -I doc/specification -I lib/
	cat .cvscopying >> ChangeLog

htmldir = ../www-$(PACKAGE)
tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`

release:
	cd lib && make release
	cvs upd -p -r HEAD NEWS > /dev/null
	if cvs upd -p -r $(tag) NEWS > /dev/null; then false else true; fi
	rm -f ChangeLog && cvs upd ChangeLog
	cvs commit
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	cvs commit -m "" ChangeLog
	cvs rtag $(tag) $(PACKAGE)
	gnupload --to alpha.gnu.org:gsasl $(distdir).tar.gz
	cd doc && ./gendocs.sh --html "--css-include=texinfo.css" \
		-o ../$(htmldir)/manual/ $(PACKAGE) "GNU SASL"
	cp -v $(distdir).tar.gz{,.sig} $(htmldir)/releases/
	cp -v doc/reference/html/*.{html,png,devhelp,css} $(htmldir)/reference/
	cd doc/doxygen && doxygen && cd ../.. && cp -v doc/doxygen/html/* $(htmldir)/doxygen/ && cd doc/doxygen/latex && make refman.pdf && cd ../../../ && cp doc/doxygen/latex/refman.pdf $(htmldir)/doxygen/$(PACKAGE).pdf
	cd $(htmldir) && cvs add -kb releases/$(distdir).tar.gz{,.sig} && \
		cvs commit -m "Update." manual/ reference/ doxygen/ releases/
