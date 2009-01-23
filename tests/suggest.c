/* suggest.c --- Test the SASL mechanism suggestion function.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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

#include "utils.h"

void
doit (void)
{
  Gsasl *ctx = NULL;
  const char *str;
  const char *p;
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  str = "FOO BAR CRAM-MD5 BAR FOO";
  p = gsasl_client_suggest_mechanism (ctx, str);
  if (debug)
    printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
  if (strcmp (p, "CRAM-MD5") != 0)
    fail ("FAIL: not cram-md5?!\n");

  str = "FOO PLAIN CRAM-MD5 BAR FOO";
  p = gsasl_client_suggest_mechanism (ctx, str);
  if (debug)
    printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
  if (strcmp (p, "CRAM-MD5") != 0)
    fail ("FAIL: not cram-md5?!\n");

  str = "FOO PLAIN BAR FOO";
  p = gsasl_client_suggest_mechanism (ctx, str);
  if (debug)
    printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
  if (strcmp (p, "PLAIN") != 0)
    fail ("FAIL: not plain?!\n");

  str = "FOO PLAIN CRAM-MD5 DIGEST-MD5 FOO";
  p = gsasl_client_suggest_mechanism (ctx, str);
  if (debug)
    printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
  if (strcmp (p, "CRAM-MD5") != 0)
    fail ("FAIL: not cram-md5?!\n");

  gsasl_done (ctx);
}
