/* Copyright (C) 2004 Simon Josefsson
   Copyright (C) 1994,1996,1997,1998,2001,2003 Free Software Foundation, Inc.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this file; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA. */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Read up to (and including) a TERMINATOR from FP into *LINEPTR
   (and null-terminate it).  *LINEPTR is a pointer returned from malloc (or
   NULL), pointing to *N characters of space.  It is realloc'ed as
   necessary.  Returns the number of characters read (not including the
   null terminator), or -1 on error or EOF.  */
ssize_t
getdelim (char **lineptr, size_t *n, int delimiter, FILE *fp)
{
  int result;
  ssize_t cur_len = 0;
  ssize_t len;

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
      size_t needed;
      char *t;
      int i;

      i = getc (fp);
      if (i == EOF)
	break;

      /* Make enough space for len+1 (for final NUL) bytes.  */
      needed = cur_len + 1;
      if (needed > *n)
	{
	  char *new_lineptr;

	  if (needed < 2 * *n)
	    needed = 2 * *n;  /* Be generous. */
	  new_lineptr = (char *) realloc (*lineptr, needed);
	  if (new_lineptr == NULL)
	    return -1;
	  *lineptr = new_lineptr;
	  *n = needed;
	}
      (*lineptr)[cur_len] = c;
      cur_len++;
    }
  (*lineptr)[cur_len] = '\0';

  return cur_len;
}
