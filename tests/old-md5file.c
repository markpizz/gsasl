/* md5file.c --- Test the MD5 file password function.
 * Copyright (C) 2002, 2003, 2004, 2005  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU SASL; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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

/* Should match values from cram-md5.pwd. */
#define BILL "bill"
#define BILL_PASSWD "hubba-hubba"

void
doit (void)
{
  char *md5file;
  char key[BUFSIZ];
  size_t keylen = BUFSIZ - 1;
  int res;

  md5file = getenv ("MD5FILE");
  if (md5file)
    {
      char *p;
      if ((p = strchr (md5file, '=')))
	md5file = p;
    }

  if (!md5file)
    md5file = "cram-md5.pwd";

  keylen = sizeof (key) - 1;
  res = gsasl_md5pwd_get_password ("non-existing-file", "user", key, &keylen);
  if (res == GSASL_FOPEN_ERROR)
    success ("non-existing-file OK\n");
  else
    fail ("non-existing-file FAIL (%d): %s\n", res, gsasl_strerror (res));

  keylen = sizeof (key) - 1;
  res = gsasl_md5pwd_get_password (md5file, BILL, key, &keylen);
  if (res == GSASL_OK)
    success ("user-found OK\n");
  else
    fail ("user-found FAIL (%d): %s\n", res, gsasl_strerror (res));
  if (keylen != strlen (BILL_PASSWD)
      || memcmp (key, BILL_PASSWD, keylen) != 0)
    fail ("user-password FAIL (%d): %.*s\n", keylen, keylen, key);
  else
    success ("user-password OK\n");

  keylen = 5;
  res = gsasl_md5pwd_get_password (md5file, BILL, key, &keylen);
  if (res == GSASL_TOO_SMALL_BUFFER)
    success ("too-small-buffer OK\n");
  else
    fail ("too-small-buffer FAIL (%d): %s\n", res, gsasl_strerror (res));

  keylen = sizeof (key) - 1;
  res = gsasl_md5pwd_get_password (md5file, "user", key, &keylen);
  if (res == GSASL_AUTHENTICATION_ERROR)
    success ("no-such-user OK\n");
  else
    fail ("no-such-user FAIL (%d): %s\n", res, gsasl_strerror (res));
}
