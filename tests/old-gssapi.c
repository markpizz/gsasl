/* old-gssapi.c --- Test the GSSAPI mechanism, using old callback API.
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

#define SERVICE "host"
#define HOST "latte.josefsson.org"
#define GSSAPI_USER "jas"

static const char *USERNAME[] = {
  "foo", "BABABA", "jas", "hepp", "@"
};
size_t i;

static int
server_cb_gssapi (Gsasl_session_ctx * ctx,
		  const char *client_name, const char *authentication_id)
{
  if (client_name)
    printf ("GSSAPI user: %s\n", client_name);

  if (authentication_id)
    printf ("Authorization ID: %s\n", authentication_id);

  if (strcmp (client_name, GSSAPI_USER) == 0 &&
      strcmp (authentication_id, USERNAME[i]) == 0)
    return GSASL_OK;
  else
    return GSASL_AUTHENTICATION_ERROR;
}

static int
server_cb_service (Gsasl_session_ctx * ctx,
		   char *srv, size_t * srvlen, char *host, size_t * hostlen)
{
  size_t srvneedlen = strlen (SERVICE);
  size_t hostneedlen = strlen (HOST);

  if (srv && *srvlen < srvneedlen)
    return GSASL_TOO_SMALL_BUFFER;

  if (host && *hostlen < hostneedlen)
    return GSASL_TOO_SMALL_BUFFER;

  *srvlen = srvneedlen;
  if (srv)
    memcpy (srv, SERVICE, *srvlen);

  *hostlen = hostneedlen;
  if (host)
    memcpy (host, HOST, *hostlen);

  return GSASL_OK;
}

static int
client_cb_authentication_id (Gsasl_session_ctx * xctx,
			     char *out, size_t * outlen)
{
  size_t needlen = strlen (USERNAME[i]);

  if (out && *outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out)
    memcpy (out, USERNAME[i], *outlen);

  return GSASL_OK;
}

static int
client_cb_service (Gsasl_session_ctx * ctx,
		   char *srv, size_t * srvlen,
		   char *host, size_t * hostlen,
		   char *srvname, size_t * srvnamelen)
{
  size_t srvneedlen = strlen (SERVICE);
  size_t hostneedlen = strlen (HOST);

  if (srv && srvlen && *srvlen < srvneedlen)
    return GSASL_TOO_SMALL_BUFFER;

  if (host && hostlen && *hostlen < hostneedlen)
    return GSASL_TOO_SMALL_BUFFER;

  if (srvlen)
    {
      *srvlen = srvneedlen;
      if (srv)
	memcpy (srv, SERVICE, *srvlen);
    }

  if (hostlen)
    {
      *hostlen = hostneedlen;
      if (host)
	memcpy (host, HOST, hostneedlen);
    }

  if (srvnamelen)
    *srvnamelen = 0;

  return GSASL_OK;
}

void
doit (void)
{
  Gsasl_ctx *ctx = NULL;
  Gsasl_session_ctx *server = NULL, *client = NULL;
  char *s1 = NULL, *s2 = NULL;
  int rc, res1, res2;

  rc = gsasl_init (&ctx);
  if (rc != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", rc, gsasl_strerror (rc));
      return;
    }

  gsasl_client_callback_service_set (ctx, client_cb_service);
  gsasl_client_callback_authentication_id_set (ctx,
					       client_cb_authentication_id);

  gsasl_server_callback_gssapi_set (ctx, server_cb_gssapi);

  for (i = 0; i < 5; i++)
    {
      rc = gsasl_server_start (ctx, "GSSAPI", &server);
      if (rc != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", rc, gsasl_strerror (rc));
	  return;
	}
      rc = gsasl_client_start (ctx, "GSSAPI", &client);
      if (rc != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", rc, gsasl_strerror (rc));
	  return;
	}

      do
	{
	  res1 = gsasl_step64 (server, s1, &s2);
	  if (s1)
	    {
	      free (s1);
	      s1 = NULL;
	    }
	  if (res1 != GSASL_OK && res1 != GSASL_NEEDS_MORE)
	    {
	      fail ("gsasl_step64 (1) failed (%d):\n%s\n", res1,
		    gsasl_strerror (res1));
	      return;
	    }

	  if (debug)
	    printf ("S: %s\n", s2);

	  if (res1 == GSASL_OK && strcmp (s2, "") == 0)
	    break;

	  res2 = gsasl_step64 (client, s2, &s1);
	  free (s2);
	  if (res2 != GSASL_OK && res2 != GSASL_NEEDS_MORE)
	    {
	      fail ("gsasl_step64 (2) failed (%d):\n%s\n", res2,
		    gsasl_strerror (res2));
	      return;
	    }

	  if (debug)
	    printf ("C: %s\n", s1);
	}
      while (res1 != GSASL_OK || res2 != GSASL_OK);

      if (s1)
	{
	  free (s1);
	  s1 = NULL;
	}

      if (debug)
	printf ("\n");

      gsasl_client_finish (client);
      gsasl_server_finish (server);
    }

  gsasl_done (ctx);
}
