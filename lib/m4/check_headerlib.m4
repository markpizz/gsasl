## check_headerlib.m4 - Idom that combine AC_CHECK_HEADER and AC_CHECK_LIB.
## Copyright (C) 2003 Simon Josefsson.                             -*-Autoconf-*-
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

# serial 1 sj_CHECK_HEADERLIB

dnl sj_CHECK_HEADERLIB(HEADER-FILE, LIBRARY, FUNCTION,
dnl                    [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
dnl                    [OTHER-LIBRARIES])
AC_DEFUN([sj_CHECK_HEADERLIB], [
	AC_CHECK_HEADER([$1], h=yes, l=no)
	AC_CHECK_LIB([$2], [$3], l=yes, l=no, [$6])
	if test "$h" = yes -a "$l" = yes; then
		LIBS="$LIBS -l$2"
		ifelse([$4], , :, [$4])
	else
		ifelse([$5], , :, [$5])
	fi])
