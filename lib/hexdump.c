/* hexdump.c	hexdump buffer
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

/**
 * gsasl_hexdump:
 * @fh: file handle
 * @buffer: input byte array
 * @len: size of input byte array
 *
 * Print a byte array to given file handle, mostly for debugging purposes.
 **/
void
gsasl_hexdump (FILE * fh, const char *buffer, size_t len)
{
  size_t i;

  for (i = 0; i < len; i++)
    {
      fprintf (fh, _("%d: hex %02X dec %d ascii %c\n"),
	       i,
	       (unsigned char) buffer[i],
	       (unsigned char) buffer[i], (unsigned char) buffer[i]);
    }
}
