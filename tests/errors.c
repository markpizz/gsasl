/* errors.c --- Test the gsasl_strerror and gsasl_strerror_name functions.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008, 2009, 2010  Simon Josefsson
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
  const char *this = NULL, *last = NULL;
  const char *name;
  int i = 0;

  do {
    last = this;

    this = gsasl_strerror (i);
    name = gsasl_strerror_name (i);

    printf ("%s (%d)\n\t%s\n", name ? name : "NULL", i, this);

    if (this == NULL)
      {
	printf ("Null error string?!\n");
	return EXIT_FAILURE;
      }

    i++;
  } while (this != last  && this != NULL);

  return EXIT_SUCCESS;
}
