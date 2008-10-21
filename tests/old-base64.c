/* old-base64.c --- Test the base64 functions, using old callback API.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <gsasl.h>

int
main (void)
{
  char target[50];
  size_t targsize = sizeof (target);
  int len;

  len = gsasl_base64_encode ("foobar", 6, target, targsize);
  printf ("base64_encode(foobar, 6) = %d, %.*s\n", len, len, target);
  if (len != 8 || memcmp (target, "Zm9vYmFy", len) != 0)
    {
      printf ("base64_encode failure\n");
      return EXIT_FAILURE;
    }

  len = gsasl_base64_decode ("Zm9vYmFy", target, targsize);
  printf ("base64_decode(Zm9vYmFy, 8) = %d, %.*s\n", len, len, target);
  if (len != 6 || memcmp (target, "foobar", len) != 0)
    {
      printf ("base64_decode failure\n");
      return EXIT_FAILURE;
    }

  return EXIT_SUCCESS;
}
