/* Copyright (C) 1994, 1996, 1997, 1998, 2001, 2003, 2004, 2005 Free
 * Software Foundation, Inc.
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

/* Ported from libc by Simon Josefsson. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Get specification.  */
#include "lgetdelim.h"

/* Get malloc. */
#include <stdlib.h>

/* Read up to (and including) a TERMINATOR from FP into *LINEPTR
   (and null-terminate it).  *LINEPTR is a pointer returned from malloc (or
   NULL), pointing to *N characters of space.  It is realloc'ed as
   necessary.  Returns the number of characters read (not including the
   null terminator), or -1 on error or EOF.  */
ssize_t
getdelim (char **lineptr, size_t *n, int delimiter, FILE *fp)
{
  ssize_t cur_len = 0;

  if (lineptr == NULL || n == NULL)
    return -1;

  if (*lineptr == NULL || *n == 0)
    {
      *n = 120;
      *lineptr = (char *) malloc (*n);
      if (*lineptr == NULL)
	return -1;
    }

  for (;;)
    {
      char *t;
      int i;

      i = getc (fp);
      if (i == EOF)
	break;

      /* Make enough space for curlen+1 bytes plus last NUL.  */
      if (cur_len + 1 >= *n)
	{
	  size_t needed = 2 * (cur_len + 1) + 1;   /* Be generous. */
	  char *new_lineptr;

	  if (needed < cur_len)
	    return -1; /* overflow */

	  new_lineptr = realloc (*lineptr, needed);
	  if (new_lineptr == NULL)
	    return -1;

	  *lineptr = new_lineptr;
	  *n = needed;
	}

      (*lineptr)[cur_len] = i;
      cur_len++;

      if (i == delimiter)
	break;
    }
  (*lineptr)[cur_len] = '\0';

  return cur_len;
}
