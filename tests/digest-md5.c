/* digest-md5.c --- Test the DIGEST-MD5 mechanism.
 * Copyright (C) 2002, 2003, 2004, 2007, 2008, 2009  Simon Josefsson
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

#include "utils.h"

#define PASSWORD "Open, Ses\xC2\xAA""me"
#define USERNAME "Ali B\xC2\xAA""ba"
/* "Ali " "\xC2\xAD" "Bab" "\xC2\xAA" */
/* "Al\xC2\xAA""dd\xC2\xAD""in\xC2\xAE" */
#define AUTHZID "joe"
#define SERVICE "imap"
#define HOSTNAME "hostname"
#define REALM "realm"

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  static int flip = 0;
  static int flip2 = 0;
  int rc = GSASL_NO_CALLBACK;

  /* Get user info from user. */

  switch (prop)
    {
    case GSASL_PASSWORD:
      gsasl_property_set (sctx, prop, PASSWORD);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHID:
      gsasl_property_set (sctx, prop, USERNAME);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHZID:
      if (flip)
	gsasl_property_set (sctx, prop, AUTHZID);
      else
	gsasl_property_set (sctx, prop, NULL);
      flip = !flip;
      rc = GSASL_OK;
      break;

    case GSASL_SERVICE:
      gsasl_property_set (sctx, prop, SERVICE);
      rc = GSASL_OK;
      break;

    case GSASL_REALM:
      if (flip2)
	gsasl_property_set (sctx, prop, REALM);
      else
	gsasl_property_set (sctx, prop, NULL);
      flip2++;
      if (flip2 == 3)
	flip2 = 0;
      rc = GSASL_OK;
      break;

    case GSASL_HOSTNAME:
      gsasl_property_set (sctx, prop, HOSTNAME);
      rc = GSASL_OK;
      break;

    case GSASL_DIGEST_MD5_HASHED_PASSWORD:
      rc = GSASL_NO_CALLBACK;
      break;

    case GSASL_QOP:
      rc = GSASL_OK;
      if (flip2 == 0)
	rc = GSASL_NO_CALLBACK;
      else if (flip2 == 1)
	gsasl_property_set (sctx, prop, "qop-auth");
      else if (flip2 == 2)
	gsasl_property_set (sctx, prop, "qop-auth,qop-int");
      break;

    default:
      fail ("Unknown callback property %d\n", prop);
      break;
    }

  return rc;
}

void
doit (void)
{
  Gsasl *ctx = NULL;
  Gsasl_session *server = NULL, *client = NULL;
  char *s1, *s2;
  size_t s1len, s2len;
  size_t i;
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  gsasl_callback_set (ctx, callback);

  for (i = 0; i < 5; i++)
    {
      res = gsasl_server_start (ctx, "DIGEST-MD5", &server);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}
      res = gsasl_client_start (ctx, "DIGEST-MD5", &client);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      /* Server begins... */

      res = gsasl_step (server, NULL, 0, &s1, &s1len);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step(1) failed (%d):\n%s\n", res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("S: %.*s\n", s1len, s1);

      /* Client respond... */

      res = gsasl_step (client, s1, s1len, &s2, &s2len);
      gsasl_free (s1);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step(2) failed (%d):\n%s\n", res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("C: %.*s\n", s2len, s2);

      /* Server finishes... */

      res = gsasl_step (server, s2, s2len, &s1, &s1len);
      gsasl_free (s2);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step(3) failed (%d):\n%s\n", res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("S: %.*s\n", s1len, s1);

      /* Client finishes... */

      res = gsasl_step (client, s1, s1len, &s2, &s2len);
      gsasl_free (s1);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step(4) failed (%d):\n%s\n", res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	{
	  /* Solaris x86 crashes here if s2 is NULL, even when s2len
	     is 0. */
	  if (s2len)
	    printf ("C: %.*s\n", s2len, s2);
	  else
	    printf ("C: \n");
	}

      /* Server is done. */

      res = gsasl_step (server, s2, s2len, &s1, &s1len);
      gsasl_free (s2);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step(5) failed (%d):\n%s\n", res,
		gsasl_strerror (res));
	  return;
	}

      if (s1len != 0)
	{
	  fail ("gsasl_step() failed, additional length=%d:\n", s1len);
	  fail ("%s\n", s1);
	  return;
	}

      gsasl_free (s1);

      if (debug)
	printf ("\n");

      gsasl_finish (client);
      gsasl_finish (server);
    }

  gsasl_done (ctx);
}
