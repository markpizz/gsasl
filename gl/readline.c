/* readline.c --- Simple replacement for readline.
 * Copyright (C) 2002, 2003, 2004, 2005  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU SASL; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdio.h>
#include <strdup.h>

#define MAX_LINE_LENGTH BUFSIZ

char *
readline (const char *prompt)
{
  char line[MAX_LINE_LENGTH];

  printf ("%s", prompt);

  line[0] = '\0';
  fgets (line, MAX_LINE_LENGTH, stdin);
  line[strlen (line) - 1] = '\0';

  return strdup (line);
}
