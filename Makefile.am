# Copyright (C) 2002-2012 Simon Josefsson
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

SUBDIRS = lib po gl src examples tests doc gltests

EXTRA_DIST = cfg.mk maint.mk .clcopying

ACLOCAL_AMFLAGS = -I m4 -I gl/m4 -I lib/m4 -I lib/gl/m4
DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --disable-obsolete
