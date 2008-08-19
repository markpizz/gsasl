# Copyright (C) 2006, 2007, 2008 Simon Josefsson.
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

CFGFLAGS ?= --enable-gtk-doc

INDENT_SOURCES = `find . -name \*.c -or -name \*.h | grep -v -e /gl -e build-aux -e /win32/`

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
.DEFAULT_GOAL := bootstrap
endif

autoreconf:
	for f in po/*.po.in lib/po/*.po.in; do \
		cp $$f `echo $$f | sed 's/.in//'`; \
	done
	mv build-aux/config.rpath build-aux/config.rpath-
	mv lib/build-aux/config.rpath lib/build-aux/config.rpath-
	test -f ./configure || autoreconf --install
	mv build-aux/config.rpath- build-aux/config.rpath
	mv lib/build-aux/config.rpath- lib/build-aux/config.rpath

update-po: refresh-po
	$(MAKE) -C lib update-po
	for f in `ls po/*.po | grep -v quot.po`; do \
		cp $$f $$f.in; \
	done
	git-add po/*.po.in
	git-commit -m "Sync with TP." po/LINGUAS po/*.po.in

bootstrap: autoreconf
	./configure $(CFGFLAGS)

W32ROOT ?= $(HOME)/w32root

mingw32: autoreconf 
	./configure $(CFGFLAGS) --host=i586-mingw32msvc --build=`./config.guess` --prefix=$(W32ROOT)
