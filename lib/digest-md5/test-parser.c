/* test-parser.c --- Self tests of DIGEST-MD5 parser.
 * Copyright (C) 2004  Simon Josefsson
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
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#include <stdio.h>

#include "parser.h"

int
main (int argc, char *argv[])
{
  digest_md5_finish tmp;
  int rc;

  {
    char *token = "rspauth=\"4711\"";

    rc = digest_md5_parse_finish (token, &tmp);
    if (rc == 0)
      printf ("`%s' -> `%s'? %s\n", token, tmp.rspauth,
	      strcmp ("4711", tmp.rspauth) == 0 ? "ok" : "FAILURE");
    else
      printf ("FAILURE\n");
  }

  {
    char *token = "rspauth=\"4711\", foo=bar";

    rc = digest_md5_parse_finish (token, &tmp);
    if (rc == 0)
      printf ("FAILURE\n");
    else
      printf ("`%s' -> invalid? ok\n", token);
  }

  {
    char *token = "rspauth=4711, foo=bar";

    rc = digest_md5_parse_finish (token, &tmp);
    if (rc == 0)
      printf ("FAILURE\n");
    else
      printf ("`%s' -> invalid? ok\n", token);
  }

  return 0;
}
