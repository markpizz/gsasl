/* openid20.c --- Test the OPENID20 mechanism.
 * Copyright (C) 2010-2012 Simon Josefsson
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

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

const char *authzid = NULL;
const char *sreg = NULL;
int validation_res = GSASL_OK;
int expect_server_res = GSASL_OK;
int expect_client_res = GSASL_OK;
int expect_server2_res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;

static int
client_callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  switch (prop)
    {
    case GSASL_AUTHZID:
      if (authzid)
	gsasl_property_set (sctx, prop, authzid);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHID:
      gsasl_property_set (sctx, prop, "http://user.example.org/");
      rc = GSASL_OK;
      break;

    case GSASL_AUTHENTICATE_IN_BROWSER:
      rc = GSASL_OK;
      break;

    default:
      fail ("Unknown client callback property %d\n", prop);
      break;
    }

  return rc;
}

static int
server_callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  switch (prop)
    {
    case GSASL_REDIRECT_URL:
      gsasl_property_set (sctx, prop,
			  "http://idp.example/NONCE/?openid.foo=bar");
      rc = GSASL_OK;
      break;

    case GSASL_VALIDATE_OPENID20:
      rc = validation_res;
      break;

    case GSASL_OPENID20_OUTCOME_DATA:
      if (sreg)
	gsasl_property_set (sctx, prop, sreg);
      rc = GSASL_OK;
      break;

    default:
      fail ("Unknown server callback property %d\n", prop);
      break;
    }

  return rc;
}

static void
openid20 (Gsasl * c, Gsasl * s)
{
  Gsasl_session *client, *server;
  char *s1, *s2;
  int res;

  /* Simple client */

  res = gsasl_client_start (c, "OPENID20", &client);
  if (res != GSASL_OK)
    {
      fail ("gsasl_client_start (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  res = gsasl_server_start (s, "OPENID20", &server);
  if (res != GSASL_OK)
    {
      fail ("gsasl_server_start (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  /* OPENID20 is client-first.  Check that server just waits. */

  res = gsasl_step64 (server, NULL, &s2);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step server0 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("S: `%s' (%d) %s\n", s2 ? s2 : "", (int) strlen (s2),
	    gsasl_strerror_name (res));

  /* The client should send the OpenID URL. */

  res = gsasl_step64 (client, s2, &s1);
  gsasl_free (s2);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step client1 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: `%s' (%d) %s\n", s1 ? s1 : "", (int) strlen (s1),
	    gsasl_strerror_name (res));

  /* The server should send the redirect URL. */

  res = gsasl_step64 (server, s1, &s2);
  gsasl_free (s1);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step server1 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("S: `%s' (%d) %s\n", s2 ? s2 : "", (int) strlen (s2),
	    gsasl_strerror_name (res));

  /* The client sends '='. */

  res = gsasl_step64 (client, s2, &s1);
  gsasl_free (s2);
  if (res != GSASL_OK)
    {
      fail ("gsasl_step client2 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: `%s' (%d) %s\n", s1 ? s1 : "", (int) strlen (s1),
	    gsasl_strerror_name (res));

  /* Now the server sends the outcome_data */

  res = gsasl_step64 (server, s1, &s2);
  gsasl_free (s1);
  if (res != expect_server_res)
    {
      fail ("gsasl_step server2 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (res == GSASL_OK || res == GSASL_NEEDS_MORE)
    {
      if (debug)
	printf ("S: `%s' (%d) %s\n", s2 ? s2 : "", (int) strlen (s2),
		gsasl_strerror_name (res));
    }

  /* The client receives the outcome data and sends a empty packet. */

  res = gsasl_step64 (client, s2, &s1);
  gsasl_free (s2);
  if (res != expect_client_res)
    {
      fail ("gsasl_step client3 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (res == GSASL_OK || res == GSASL_NEEDS_MORE)
    {
      if (debug)
	printf ("C: `%s' (%d) %s\n", s1 ? s1 : "", (int) strlen (s1),
		gsasl_strerror_name (res));
    }
  else if (debug)
    {
      printf ("C: %s\n", gsasl_strerror_name (res));
      s1 = NULL;
    }

  /* The server should reject authentication at this point */

  res = gsasl_step64 (server, s1, &s2);
  gsasl_free (s1);
  if (res != expect_server2_res)
    {
      fail ("gsasl_step server3 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (res == GSASL_OK || res == GSASL_NEEDS_MORE)
    {
      if (debug)
	printf ("S: `%s' (%d) %s\n", s2 ? s2 : "", (int) strlen (s2),
		gsasl_strerror_name (res));
    }
  else if (debug)
    {
      printf ("S: %s\n", gsasl_strerror_name (res));
      s2 = NULL;
    }

  /* The client should be called too many times now */

  res = gsasl_step64 (client, s2, &s1);
  gsasl_free (s2);
  if (res != GSASL_MECHANISM_CALLED_TOO_MANY_TIMES)
    {
      fail ("gsasl_step client4 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: %s\n", gsasl_strerror_name (res));

  if (authzid == NULL && gsasl_property_fast (server, GSASL_AUTHZID) == NULL)
    success ("expected and got no authzid\n");
  else if (!authzid && gsasl_property_fast (server, GSASL_AUTHZID))
    fail ("got unexpected authzid? %s\n",
	  gsasl_property_fast (server, GSASL_AUTHZID));
  else if (authzid && !gsasl_property_fast (server, GSASL_AUTHZID))
    fail ("did not get authzid? %s\n", authzid);
  else if (strcmp (authzid, gsasl_property_fast (server, GSASL_AUTHZID)) != 0)
    fail ("authzid comparison failed: got %s expected %s\n",
	  gsasl_property_fast (server, GSASL_AUTHZID), authzid);

  gsasl_finish (client);
  gsasl_finish (server);
}

void
doit (void)
{
  Gsasl *c = NULL, *s = NULL;
  int res;

  res = gsasl_init (&c);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  res = gsasl_init (&s);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (!gsasl_client_support_p (c, "OPENID20"))
    {
      gsasl_done (c);
      fail ("No support for OPENID20 clients.\n");
      exit (77);
    }

  if (!gsasl_server_support_p (s, "OPENID20"))
    {
      gsasl_done (s);
      fail ("No support for OPENID20 servers.\n");
      exit (77);
    }

  gsasl_callback_set (c, client_callback);
  gsasl_callback_set (s, server_callback);

  printf ("Running successful authentication without SREG.\n");
  openid20 (c, s);

  printf ("Running successful authentication with SREG.\n");
  sreg = "nickname=jas";
  openid20 (c, s);

  authzid = "user";
  printf ("Running successful authentication without SREG with authzid.\n");
  openid20 (c, s);

  printf ("Running successful authentication with SREG with authzid.\n");
  sreg = "nickname=jas";
  openid20 (c, s);

  printf ("Running failed authentication.\n");
  validation_res = GSASL_AUTHENTICATION_ERROR;
  expect_server_res = GSASL_NEEDS_MORE;
  expect_client_res = GSASL_NEEDS_MORE;
  expect_server2_res = GSASL_AUTHENTICATION_ERROR;
  openid20 (c, s);

  gsasl_done (c);
  gsasl_done (s);
}
