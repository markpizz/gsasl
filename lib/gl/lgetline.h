/* Copyright (C) 2004, 2005 Free Software Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  */

/* Written by Simon Josefsson. */

#ifndef GNULIB_GETLINE_H
# define GNULIB_GETLINE_H

/* Get getline, if available.  */
#include <stdio.h>

#if defined HAVE_DECL_GETLINE && !HAVE_DECL_GETLINE
/* Get size_t. */
# include <stddef.h>

/* Get ssize_t.  */
# include <sys/types.h>

extern ssize_t getline (char **lineptr, size_t *n, FILE *stream);
#endif

#endif /* GNULIB_GETLINE_H */
