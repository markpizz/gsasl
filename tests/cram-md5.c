/* cram-md5.c --- Test the CRAM-MD5 mechanism.
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
  if (!key)
    *keylen = strlen (PASSWORD);

  if (*keylen < strlen (PASSWORD))
    return GSASL_TOO_SMALL_BUFFER;

  if (key)
    memcpy (key, PASSWORD, *keylen);

  return GSASL_OK;
}

static int
client_cb_authentication_id (Gsasl_session_ctx * xctx,
			     char *out, size_t * outlen)
{
  if (!out)
    *outlen = strlen (USERNAME);

  if (*outlen < strlen (USERNAME))
    return GSASL_TOO_SMALL_BUFFER;

  if (out)
    memcpy (out, USERNAME, *outlen);

  return GSASL_OK;
}

static int
client_cb_password (Gsasl_session_ctx * xctx, char *out, size_t * outlen)
{
  if (!out)
    *outlen = strlen (PASSWORD);

  if (*outlen < strlen (PASSWORD))
    return GSASL_TOO_SMALL_BUFFER;

  if (out)
    memcpy (out, PASSWORD, *outlen);

  return GSASL_OK;
}

void
doit (void)
{
  Gsasl_ctx *ctx = NULL;
  Gsasl_session_ctx *server = NULL, *client = NULL;
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

  gsasl_server_callback_retrieve_set (ctx, server_cb_retrieve);

  gsasl_client_callback_authentication_id_set (ctx,
					       client_cb_authentication_id);
  gsasl_client_callback_password_set (ctx, client_cb_password);


  for (i = 0; i < 5; i++)
    {
      res = gsasl_server_start (ctx, "CRAM-MD5", &server);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}
      res = gsasl_client_start (ctx, "CRAM-MD5", &client);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
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

      res = gsasl_step (client, s1, s1len, &s2, &s2len);
      free (s1);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step() failed (%d):\n%s\n", res, gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("C: %.*s\n", s2len, s2);

      res = gsasl_step (server, s2, s2len, &s1, &s1len);
      free (s2);
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

      free (s1);

      if (debug)
	printf ("\n");

      gsasl_client_finish (client);
      gsasl_server_finish (server);
    }

  gsasl_done (ctx);
}
