/* Declare a dummy symbol, to prevent empty libraries from breaking builds.
   Copyright (C) 2004 Simon Josefsson

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU Library General Public License as published
   by the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
   USA.  */

/*
 * Some systems, reportedly OpenBSD and mac OS X, refuse to create
 * libraries without any symbols.  You might get an error like:
 *
 * > ar cru .libs/libgl.a
 * > ar: no archive members specified
 *
 * Defining a static symbol, as is done in this file, and adding the
 * file to the library, will prevent the library from being empty.
 *
 */

static char *to_prevent_empty_libraries;
