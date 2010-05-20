/* cram-md5.c --- Test the CRAM-MD5 mechanism.
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

#include "utils.h"

#define PASSWORD "Open, Sesame"
#define USERNAME "Ali Baba"
/* "Ali " "\xC2\xAD" "Bab" "\xC2\xAA" */
/* "Al\xC2\xAA""dd\xC2\xAD""in\xC2\xAE" */


static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  /* Get user info from user. */

  switch (prop)
    {
    case GSASL_PASSWORD:
      gsasl_property_set (sctx, GSASL_PASSWORD, PASSWORD);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHID:
      gsasl_property_set (sctx, GSASL_AUTHID, USERNAME);
      rc = GSASL_OK;
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
  char *last_server_challenge = NULL;
  size_t last_server_challenge_len = 0;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (!gsasl_client_support_p (ctx, "CRAM-MD5")
      || !gsasl_server_support_p (ctx, "CRAM-MD5"))
    {
      gsasl_done (ctx);
      fail("No support for CRAM-MD5.\n");
      exit(77);
    }

  gsasl_callback_set (ctx, callback);

  for (i = 0; i < 5; i++)
    {
      res = gsasl_server_start (ctx, "CRAM-MD5", &server);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_server_start() failed (%d):\n%s\n",
		res, gsasl_strerror (res));
	  return;
	}
      res = gsasl_client_start (ctx, "CRAM-MD5", &client);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_client_start() failed (%d):\n%s\n",
		res, gsasl_strerror (res));
	  return;
	}

      res = gsasl_step (server, NULL, 0, &s1, &s1len);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("S: %.*s\n", s1len, s1);

      if (last_server_challenge)
	{
	  if (last_server_challenge_len == s1len &&
	      memcmp (last_server_challenge, s1, s1len) == 0)
	    fail ("Server challenge same as last one!\n");

	  free (last_server_challenge);
	}

      last_server_challenge = malloc (s1len);
      if (!last_server_challenge)
	fail ("malloc() failure (%d)\n", s1len);
      memcpy (last_server_challenge, s1, s1len);
      last_server_challenge_len = s1len;

      res = gsasl_step (client, s1, s1len, &s2, &s2len);
      gsasl_free (s1);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("C: %.*s\n", s2len, s2);

      res = gsasl_step (server, s2, s2len, &s1, &s1len);
      gsasl_free (s2);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step() failed (%d):\n%s\n", res, gsasl_strerror (res));
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

  free (last_server_challenge);

  gsasl_done (ctx);
}
