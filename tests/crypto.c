/* crypto.c --- Test the crypto related SASL functions.
 * Copyright (C) 2009-2012 Simon Josefsson
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
#include <stdlib.h>
#include <string.h>
#include <gsasl.h>

#include "utils.h"

void
doit (void)
{
#define SIZE 10
  char tmp[SIZE];
  char savetmp[SIZE];
  char *hash;
  size_t tmplen;
  int rc;
  Gsasl *ctx;

  rc = gsasl_init (&ctx);
  if (rc != GSASL_OK)
    fail ("gsasl_init %d: %s\n", rc, gsasl_strerror (rc));

  memset (tmp, 42, SIZE);
  memcpy (savetmp, tmp, SIZE);
  tmplen = sizeof (tmp);
  rc = gsasl_nonce (tmp, tmplen);
  if (rc != GSASL_OK)
    fail ("gsasl_nonce %d: %s\n", rc, gsasl_strerror (rc));
  if (memcmp (savetmp, tmp, SIZE) == 0)
    fail ("gsasl_nonce memcmp fail\n");
  success("gsasl_nonce\n");

  memcpy (savetmp, tmp, SIZE);
  tmplen = sizeof (tmp);
  rc = gsasl_random (tmp, tmplen);
  if (rc != GSASL_OK)
    fail ("gsasl_random %d: %s\n", rc, gsasl_strerror (rc));
  if (memcmp (savetmp, tmp, SIZE) == 0)
    fail ("gsasl_random memcmp fail\n");
  success("gsasl_random\n");

  rc = gsasl_md5 ("abc", 3, &hash);
  if (rc != GSASL_OK)
    fail ("gsasl_md5 %d: %s\n", rc, gsasl_strerror (rc));
  if (memcmp (hash, "\x90\x01\x50\x98\x3C\xD2\x4F\xB0"
	      "\xD6\x96\x3F\x7D\x28\xE1\x7F\x72", 16) != 0)
    fail ("gsasl_md5 memcmp fail\n");
  success("gsasl_md5\n");
  gsasl_free (hash);

  rc = gsasl_hmac_md5 ("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		       "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16,
		       "Hi There", 8, &hash);
  if (rc != GSASL_OK)
    fail ("gsasl_hmac_md5 %d: %s\n", rc, gsasl_strerror (rc));
  if (memcmp (hash, "\x92\x94\x72\x7a\x36\x38\xbb\x1c"
	      "\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d", 16) != 0)
    fail ("gsasl_hmac_md5 memcmp fail\n");
  success("gsasl_hmac_md5\n");
  gsasl_free (hash);

  rc = gsasl_sha1 ("abc", 3, &hash);
  if (rc != GSASL_OK)
    fail ("gsasl_sha1 %d: %s\n", rc, gsasl_strerror (rc));
  if (memcmp (hash, "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25"
	      "\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d", 20) != 0)
    fail ("gsasl_sha1 memcmp fail\n");
  success("gsasl_sha1\n");
  gsasl_free (hash);

  rc = gsasl_hmac_sha1 ("\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
			"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 16,
			"Hi There", 8, &hash);
  if (rc != GSASL_OK)
    fail ("gsasl_hmac_sha1 %d: %s\n", rc, gsasl_strerror (rc));
  if (memcmp (hash, "\x67\x5b\x0b\x3a\x1b\x4d\xdf\x4e\x12\x48\x72"
	      "\xda\x6c\x2f\x63\x2b\xfe\xd9\x57\xe9", 20) != 0)
    fail ("gsasl_hmac_sha1 memcmp fail\n");
  success("gsasl_hmac_sha1\n");
  gsasl_free (hash);

  gsasl_done (ctx);
}
