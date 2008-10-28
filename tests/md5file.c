/* md5file.c --- Test the MD5 file password function.
 * Copyright (C) 2002, 2003, 2004, 2007, 2008  Simon Josefsson
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

/* Should match values from cram-md5.pwd. */
#define BILL "bill"
#define BILL_PASSWD "hubba-hubba"

void
doit (void)
{
  char *md5file;
  char *key;
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

  res = gsasl_simple_getpass ("non-existing-file", "user", &key);
  if (res == GSASL_AUTHENTICATION_ERROR)
    success ("non-existing-file OK\n");
  else
    fail ("non-existing-file FAIL (%d): %s\n", res, gsasl_strerror (res));

  res = gsasl_simple_getpass (md5file, BILL, &key);
  if (res == GSASL_OK)
    success ("user-found OK\n");
  else
    fail ("user-found FAIL (%d): %s\n", res, gsasl_strerror (res));
  if (strcmp (key, BILL_PASSWD) != 0)
    fail ("user-password FAIL: %s\n", key);
  else
    success ("user-password OK\n");
  if (res == GSASL_OK)
    gsasl_free (key);

  res = gsasl_simple_getpass (md5file, "user", &key);
  if (res == GSASL_AUTHENTICATION_ERROR)
    success ("no-such-user OK\n");
  else
    fail ("no-such-user FAIL (%d): %s\n", res, gsasl_strerror (res));
}
