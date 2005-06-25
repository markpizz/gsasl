/* external.c --- Test the EXTERNAL mechanism.
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

#include "utils.h"

static const struct {
  char *sendauthzid;
  char *recvauthzid;
  int clientrc;
  int callbackrc;
  int serverrc;
} tv[] = {
  { NULL, "", GSASL_OK, GSASL_OK, GSASL_OK },
  { "", "", GSASL_OK, GSASL_OK, GSASL_OK },
  { "foo", "foo", GSASL_OK, GSASL_OK, GSASL_OK },
  { "foo", "foo", GSASL_OK, GSASL_NO_CALLBACK, GSASL_NO_CALLBACK },
  { "foo\0bar", "foo", GSASL_OK, GSASL_OK, GSASL_OK },
  { "foo\0bar", "foo", GSASL_OK, GSASL_AUTHENTICATION_ERROR,
    GSASL_AUTHENTICATION_ERROR }
};

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  static int c = 0;
  static int s = 0;
  int rc = GSASL_NO_CALLBACK;

  c = c % sizeof (tv) / sizeof (tv[0]);
  s = s % sizeof (tv) / sizeof (tv[0]);

  /* Get user info from user. */

  switch (prop)
    {
    case GSASL_AUTHZID:
      gsasl_property_set (sctx, prop, tv[c++].sendauthzid);
      rc = GSASL_OK;
      break;

    case GSASL_VALIDATE_EXTERNAL:
      rc = tv[s++].callbackrc;
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

  for (i = 0; i < 2 * (sizeof (tv) / sizeof (tv[0])); i++)
    {
      int n = i % sizeof (tv) / sizeof (tv[0]);

      res = gsasl_server_start (ctx, "EXTERNAL", &server);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_server_start (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}
      res = gsasl_client_start (ctx, "EXTERNAL", &client);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_client_start (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      res = gsasl_step (server, NULL, 0, &s1, &s1len);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step server1 (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      if (debug)
	if (s1)
	  printf ("S[%d]: `%.*s' (%d)\n", i, s1len, s1, s1len);
	else
	  printf ("S[%d] NULL\n", i);

      res = gsasl_step (client, s1, s1len, &s2, &s2len);
      if (res != tv[n].clientrc)
	{
	  fail ("gsasl_step client1 (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}
      if (s1)
	free (s1);

      if (debug)
	if (s2)
	  printf ("C[%d]: `%.*s' (%d)\n", i, s2len, s2, s2len);
	else
	  printf ("C[%d] NULL\n", i);

      res = gsasl_step (server, s2, s2len, &s1, &s1len);
      if (s2)
	free (s2);
      if (res != tv[n].serverrc)
	{
	  fail ("gsasl_step server2 (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      if (s1len != 0)
	{
	  fail ("gsasl_step() failed, additional length=%d:\n%s", s1len, s1);
	  return;
	}

      if (memcmp (s1, tv[n].recvauthzid, s1len) != 0)
	{
	  fail ("gsasl_step() failed, recv authzid mismatch: `%s' != `%s'\n",
		s1, tv[n].recvauthzid);
	  return;
	}

      if (s1)
	free (s1);

      gsasl_finish (client);
      gsasl_finish (server);
    }

  gsasl_done (ctx);
}
