/* Copyright (C) 2004 Simon Josefsson

   The file is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this file; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA.  */

#ifndef GETLINE_H_
# define GETLINE_H_

/* Get getline, if available.  */
#include <stdio.h>

#if defined HAVE_DECL_GETLINE && !HAVE_DECL_GETLINE
/* Like getdelim, but always looks for a newline.  */
ssize_t getline (char **lineptr, size_t *n, FILE *stream);
#endif

#endif /* GETLINE_H_ */
