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
  digest_md5_challenge c;
  digest_md5_response r;
  digest_md5_finish f;
  int rc;

  {
    char *token = "nonce=4711, foo=bar";

    printf ("`%s': ", token);
    rc = digest_md5_parse_challenge (token, &c);
    if (rc == 0)
      printf ("nonce `%s': %s", c.nonce,
	      strcmp ("4711", c.nonce) == 0 ? "PASS" : "FAILURE");
    else
      printf ("FAILURE");
    printf ("\n");
  }

  {
    char *token = "bar=foo, foo=bar";

    printf ("`%s': ", token);
    rc = digest_md5_parse_challenge (token, &c);
    if (rc == 0)
      printf ("FAILURE");
    else
      printf ("PASS");
    printf ("\n");
  }

  {
    char *token = "realm=foo, realm=bar, nonce=42";

    printf ("`%s': ", token);
    rc = digest_md5_parse_challenge (token, &c);
    if (rc == 0)
      {
	if (c.nrealms == 2)
	  printf ("realms `%s', `%s' PASS", c.realms[0], c.realms[1]);
	else
	  printf ("nrealms %d != 2", c.nrealms);
      }
    else
      printf ("FAILURE");
    printf ("\n");
  }

  /* Response */

  {
    char *token = "bar=foo, foo=bar";

    printf ("response `%s': ", token);
    rc = digest_md5_parse_response (token, &r);
    if (rc == 0)
      printf ("FAILURE");
    else
      printf ("PASS");
    printf ("\n");
  }

  {
    char *token = "username=jas, nonce=42, cnonce=4711, nc=00000001, "
      "digest-uri=foo, response=apa";

    printf ("response `%s': ", token);
    rc = digest_md5_parse_response (token, &r);
    if (rc == 0)
      printf ("username `%s', nonce `%s', cnonce `%s',"
	      " nc %08lx, digest-uri `%s', response `%s': PASS",
	      r.username, r.nonce, r.cnonce, r.nc, r.digesturi, r.response);
    else
      printf ("FAILURE");
    printf ("\n");
  }

  /* Auth-response, finish. */

  {
    char *token = "rspauth=\"4711\"";

    rc = digest_md5_parse_finish (token, &f);
    if (rc == 0)
      printf ("`%s' -> `%s'? %s\n", token, f.rspauth,
	      strcmp ("4711", f.rspauth) == 0 ? "ok" : "FAILURE");
    else
      printf ("FAILURE\n");
  }

  {
    char *token = "bar=foo, foo=bar";

    rc = digest_md5_parse_finish (token, &f);
    if (rc == 0)
      printf ("FAILURE\n");
    else
      printf ("`%s' -> invalid? ok\n", token);
  }

  return 0;
}
