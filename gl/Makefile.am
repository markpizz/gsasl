## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004 Simon Josefsson.
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

# gnulib modules: dummy fatal error strdup getopt progname

AUTOMAKE_OPTIONS = 1.5 gnits no-dependencies

noinst_LTLIBRARIES = libgl.la

libgl_la_SOURCES =
libgl_la_LIBADD = @LTLIBOBJS@
EXTRA_DIST =
BUILT_SOURCES =
SUFFIXES =
MOSTLYCLEANFILES =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
libgl_la_SOURCES += dummy.c


libgl_la_SOURCES += exit.h


libgl_la_SOURCES += fatal.h fatal.c

BUILT_SOURCES += $(GETOPT_H)
EXTRA_DIST += getopt_.h getopt_int.h

# We need the following in order to create an <getopt.h> when the system
# doesn't have one that works with the given compiler.
all-local $(libgl_la_OBJECTS): $(GETOPT_H)
getopt.h: getopt_.h
	cp $(srcdir)/getopt_.h $@-t
	mv $@-t $@
MOSTLYCLEANFILES += getopt.h getopt.h-t

libgl_la_SOURCES += gettext.h

libgl_la_SOURCES += progname.h progname.c

libgl_la_SOURCES += strdup.h

libgl_la_SOURCES += unlocked-io.h

# Local additions

libgl_la_SOURCES += getpassword.h getpassword.c
if !READLINE
libgl_la_SOURCES += readline.c
endif
