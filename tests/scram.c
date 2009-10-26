/* scram.c --- Test the SCRAM mechanism.
 * Copyright (C) 2009  Simon Josefsson
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
#define AUTHZID "joe"

#define EXPECTED_USERNAME "Ali Baba"

size_t i;

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
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
      if (i & 0x01)
	{
	  gsasl_property_set (sctx, prop, AUTHZID);
	  rc = GSASL_OK;
	}
      break;

    case GSASL_SCRAM_ITER:
      if (strcmp (gsasl_property_fast (sctx, GSASL_AUTHID),
		  EXPECTED_USERNAME) != 0)
	fail ("Username mismatch: %s",
	      gsasl_property_fast (sctx, GSASL_AUTHID));
      if (i & 0x02)
	{
	  gsasl_property_set (sctx, prop, "1234");
	  rc = GSASL_OK;
	}
      break;

    case GSASL_SCRAM_SALT:
      if (i & 0x04)
	{
	  gsasl_property_set (sctx, prop, "c2FsdA==");
	  rc = GSASL_OK;
	}
      break;

    case GSASL_SCRAM_SALTED_PASSWORD:
      if (i & 0x04 && i & 0x08) /* Only works with fixed salt. */
	{
	  const char *str[] = {
	    "06bfd2d70a0fa425c20473722a93700df39f3cbd",
	    "f1e6c0e5a207367176ac42c7799b67ae3e097d7e",
	  };
	  /* >>1 to mask out authzid. */
	  size_t pos = (i & ~0x04 & ~0x08) >> 1;
	  gsasl_property_set (sctx, prop, str[pos]);
	  rc = GSASL_OK;
	}
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
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (!gsasl_client_support_p (ctx, "SCRAM-SHA-1")
      || !gsasl_server_support_p (ctx, "SCRAM-SHA-1"))
    {
      gsasl_done (ctx);
      fail("No support for SCRAM-SHA-1.\n");
      exit(77);
    }

  gsasl_callback_set (ctx, callback);

  for (i = 0; i <= 15; i++)
    {
      if (debug)
	printf ("Iteration %d ...\n", i);

      res = gsasl_server_start (ctx, "SCRAM-SHA-1", &server);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}
      res = gsasl_client_start (ctx, "SCRAM-SHA-1", &client);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      /* Client first... */

      res = gsasl_step (client, NULL, 0, &s1, &s1len);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step[%d](1) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("C: %.*s\n", s1len, s1);

      /* Server first... */

      res = gsasl_step (server, s1, s1len, &s2, &s2len);
      gsasl_free (s1);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step[%d](2) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("S: %.*s\n", s2len, s2);

      /* Client final... */

      res = gsasl_step (client, s2, s2len, &s1, &s1len);
      gsasl_free (s2);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step[%d](3) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("C: %.*s\n", s1len, s1);

      /* Server final... */

      res = gsasl_step (server, s1, s1len, &s2, &s2len);
      gsasl_free (s1);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step[%d](4) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("S: %.*s\n", s2len, s2);

      /* Let client parse server final... */

      res = gsasl_step (client, s2, s2len, &s1, &s1len);
      gsasl_free (s2);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step[%d](5) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("C: %.*s\n\n", s1len, s1);

      gsasl_finish (client);
      gsasl_finish (server);
    }

  gsasl_done (ctx);
}
