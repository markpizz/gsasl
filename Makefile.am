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

DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc

EXTRA_DIST = ANNOUNCE config.h.in config.rpath mkinstalldirs libgsasl.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgsasl.pc

SUBDIRS = m4 po gl lib src tests doc

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

# Maintainer targets

ChangeLog:
	test ! -f .cvsusers || \
	(cvs2cl --fsf --FSF --usermap .cvsusers \
	-I "ChangeLog|.cvs|autogen.sh|doc/specification|libstringprep" && \
	cat .cvscopying >> ChangeLog)

indent:
	(cd lib && make indent)
	(cd src && make indent)
	(cd tests && make indent)

htmldir = ../www-$(PACKAGE)
tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`

release:
	cvs upd -p -r HEAD NEWS > /dev/null
	if cvs upd -p -r $(tag) NEWS > /dev/null; then false else true; fi
	rm -f ChangeLog && cvs upd ChangeLog
	cvs commit
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	cvs commit -m "" ChangeLog
	rm -f $(distdir).tar.gz.asc
	gpg -a --sign --detach $(distdir).tar.gz
	gpg --verify $(distdir).tar.gz.asc
	cvs rtag $(tag) $(PACKAGE)
	test -d $(htmldir) && cp -v doc/$(PACKAGE).{ps,pdf,html} $(htmldir)/
	test -d $(htmldir)/reference/html && \
		cp -v reference/html/*.{html,png} $(htmldir)/reference/
	test -d $(htmldir) && cd $(htmldir) && cvs commit -m "Update." \
		$(PACKAGE).{ps,pdf,html} reference/*.html
