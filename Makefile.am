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

EXTRA_DIST = ANNOUNCE libgsasl.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgsasl.pc

SUBDIRS = po 
if NETTLE
SUBDIRS += crypto
endif
SUBDIRS += lib src tests doc

ACLOCAL_AMFLAGS = -I m4

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
	-cd doc/doxygen && doxygen && cd ../.. && cp -v doc/doxygen/html/* $(htmldir)/doxygen/ && cd doc/doxygen/latex && make ps pdf && cd ../../../ && cp doc/doxygen/latex/refman.pdf $(htmldir)/doxygen/$(PACKAGE).pdf && cp doc/doxygen/latex/refman.ps $(htmldir)/doxygen/$(PACKAGE).ps
	-cp -v doc/reference/*.{html,png} $(htmldir)/reference/
	-cd doc && ./gendocs.sh -o ../$(htmldir)/manual/ $(PACKAGE) "GNU SASL"
	-cd $(htmldir) && \
		cvs commit -m "Update." manual/ reference/ doxygen/
