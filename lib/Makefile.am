## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004 Simon Josefsson.
#
# This file is part of GNU SASL Library.
#
# GNU SASL Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU SASL Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU SASL Library; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgsasl.pc

SUBDIRS = po gl

if NETTLE
SUBDIRS += crypto
endif

# Plugins:
if EXTERNAL
SUBDIRS += external
endif

if ANONYMOUS
SUBDIRS += anonymous
endif

if PLAIN
SUBDIRS += plain
endif

if LOGIN
SUBDIRS += login
endif

if CRAM_MD5
SUBDIRS += cram-md5
endif

if DIGEST_MD5
SUBDIRS += digest-md5
endif

if NTLM
SUBDIRS += ntlm
endif

if GSSAPI
SUBDIRS += gssapi
endif			

if SECURID
SUBDIRS += securid
endif			

if KERBEROS_V5
SUBDIRS += kerberos_v5
endif

SUBDIRS += src

# Maintainer targets

ChangeLog:
	cvs2cl --fsf --FSF --usermap ../.cvsusers -I ChangeLog -I .cvs \
		-I autogen.sh
	cat ../.cvscopying >> ChangeLog
