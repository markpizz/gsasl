/* old-gssapi.c --- Test the GSSAPI mechanism, using old callback API.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
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
 * along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#define PASSWORD "Open, Sesame"
#define USERNAME "Ali Baba"
/* "Ali " "\xC2\xAD" "Bab" "\xC2\xAA" */
/* "Al\xC2\xAA""dd\xC2\xAD""in\xC2\xAE" */

static int
server_cb_retrieve (Gsasl_session_ctx * xctx,
		    const char *authentication_id,
		    const char *authorization_id,
		    const char *realm, char *key, size_t * keylen)
{
  size_t needlen = strlen (PASSWORD);

  if (key && *keylen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *keylen = needlen;
  if (key)
    memcpy (key, PASSWORD, *keylen);

  return GSASL_OK;
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
server_cb_gssapi (Gsasl_session_ctx * ctx,
		  const char *client_name, const char *authentication_id)
{
  char *data;

  if (client_name)
    printf ("GSSAPI user: %s\n", client_name);

  if (authentication_id)
    printf ("Authentication ID: %s\n", authentication_id);

  data = readline ("Admit user? (y/n) ");

  if (*data == 'y' || *data == 'Y')
    return GSASL_OK;
  else
    return GSASL_AUTHENTICATION_ERROR;
}

static int
client_cb_authentication_id (Gsasl_session_ctx * xctx,
			     char *out, size_t * outlen)
{
  size_t needlen = strlen (USERNAME);

  if (out && *outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out)
    memcpy (out, USERNAME, *outlen);

  return GSASL_OK;
}

static int
client_cb_password (Gsasl_session_ctx * xctx, char *out, size_t * outlen)
{
  size_t needlen = strlen (PASSWORD);

  if (out && *outlen < needlen)
    return GSASL_TOO_SMALL_BUFFER;

  *outlen = needlen;
  if (out)
    memcpy (out, PASSWORD, *outlen);

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
  size_t i;
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  gsasl_server_callback_retrieve_set (ctx, server_cb_retrieve);
  gsasl_server_callback_service_set (ctx, server_cb_service);
  gsasl_server_callback_gssapi_set (ctx, server_cb_gssapi);

  gsasl_client_callback_authentication_id_set (ctx,
					       client_cb_authentication_id);
  gsasl_client_callback_password_set (ctx, client_cb_password);
  gsasl_client_callback_service_set (ctx, client_cb_service);

  for (i = 0; i < 5; i++)
    {
      res = gsasl_server_start (ctx, "GSSAPI", &server);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}
      res = gsasl_client_start (ctx, "GSSAPI", &client);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      do
	{
	  res = gsasl_step64 (server, s1, &s2);
	  if (s1)
	    free (s1);
	  if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	    {
	      fail ("gsasl_step64 (1) failed (%d):\n%s\n", res,
		    gsasl_strerror (res));
	      return;
	    }

	  if (debug)
	    printf ("S: %s\n", s2);

	  res = gsasl_step64 (client, s2, &s1);
	  free (s2);
	  if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	    {
	      fail ("gsasl_step64 (2) failed (%d):\n%s\n", res,
		    gsasl_strerror (res));
	      return;
	    }

	  if (debug)
	    printf ("C: %s\n", s1);
	}
      while (res != GSASL_OK);

      free (s1);
      s1 = NULL;

      if (debug)
	printf ("\n");

      gsasl_client_finish (client);
      gsasl_server_finish (server);
    }

  gsasl_done (ctx);
}
