## Process this file with automake to produce Makefile.in
# Copyright (C) 2002 Simon Josefsson.
#
# This file is part of Libgsasl.
#
# Libgsasl is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Libgsasl is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

DISTCHECK_CONFIGURE_FLAGS = --without-included-gettext

EXTRA_DIST = config.h.in config.rpath mkinstalldirs libgsasl.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgsasl.pc

MOST_SUBDIRS = m4 intl po argp lib src tests doc

DIST_SUBDIRS = libstringprep $(MOST_SUBDIRS)

SUBDIRS = @LIBSTRINGPREP@ $(MOST_SUBDIRS)

ACLOCAL_AMFLAGS = -I m4 -I argp

ChangeLog:
	cvs2cl --fsf --usermap .cvsusers --separate-header -I \
	"ChangeLog|.cvsignore|.cvsusers|autogen.sh|doc/specification/.*"

indent:
	(cd lib && make indent)
	(cd src && make indent)
	(cd tests && make indent)

sign: $(distdir).tar.gz
	gpg -a --sign --detach $(distdir).tar.gz
	gpg --verify $(distdir).tar.gz.asc
