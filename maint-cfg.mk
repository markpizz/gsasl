# Copyright (C) 2006 Simon Josefsson.
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

CFGFLAGS ?= --enable-gtk-doc

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
.DEFAULT_GOAL := bootstrap
endif

autoreconf:
	test -f ./configure || autoreconf --install

bootstrap: autoreconf
	./configure $(CFGFLAGS)

W32ROOT ?= $(HOME)/w32root

mingw32: autoreconf 
	./configure $(CFGFLAGS) --host=i586-mingw32msvc --build=`./config.guess` --prefix=$(W32ROOT)
