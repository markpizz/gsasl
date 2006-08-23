/* test-parser.c --- Self tests of GS2 parser & printer.
 * Copyright (C) 2006  Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gs2parser.h"

int
main (int argc, char *argv[])
{
  gs2_token tok;
  int rc;

  {
    char *token = "\x00\x00\x00\x00";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc >= 0)
      abort ();
  }

  {
    char *token = "\x00\x00\x00\x04";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc >= 0)
      abort ();
  }

  return 0;
}
