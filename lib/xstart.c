/* xstart.c	start libgsasl session
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

static _Gsasl_mechanism *
_gsasl_find_mechanism (const char *mech,
		       size_t n_mechs, _Gsasl_mechanism * mechs)
{
  size_t i;

  if (mech == NULL)
    return NULL;

  for (i = 0; i < n_mechs; i++)
    if (strcmp (mech, mechs[i].name) == 0)
      return &mechs[i];

  return NULL;
}

static int
_gsasl_setup (Gsasl_ctx * ctx,
	      const char *mech,
	      Gsasl_session_ctx * sctx,
	      size_t n_mechs, _Gsasl_mechanism * mechs, int clientp)
{
  _Gsasl_mechanism *mechptr = NULL;
  int res;

  mechptr = _gsasl_find_mechanism (mech, n_mechs, mechs);
  if (mechptr == NULL)
    return GSASL_UNKNOWN_MECHANISM;

  sctx->ctx = ctx;
  sctx->mech = mechptr;
  sctx->clientp = clientp;

  if (clientp)
    {
      if (sctx->mech->client.start)
	res = sctx->mech->client.start (sctx, &sctx->mech_data);
      else
	res = GSASL_NO_CLIENT_CODE;
    }
  else
    {
      if (sctx->mech->server.start)
	res = sctx->mech->server.start (sctx, &sctx->mech_data);
      else
	res = GSASL_NO_SERVER_CODE;
    }
  if (res != GSASL_OK)
    return res;

  return GSASL_OK;
}

static int
_gsasl_start (Gsasl_ctx * ctx,
	      const char *mech,
	      Gsasl_session_ctx ** sctx,
	      size_t n_mechs, _Gsasl_mechanism * mechs, int clientp)
{
  Gsasl_session_ctx *out;
  int res;

  out = (Gsasl_session_ctx *) malloc (sizeof (*out));
  if (out == NULL)
    return GSASL_MALLOC_ERROR;

  memset (out, 0, sizeof (*out));

  res = _gsasl_setup (ctx, mech, out, n_mechs, mechs, clientp);
  if (res != GSASL_OK)
    {
      free (out);
      return res;
    }

  *sctx = out;

  return GSASL_OK;
}

/**
 * gsasl_client_start:
 * @ctx: libgsasl handle.
 * @mech: name of SASL mechanism.
 * @sctx: pointer to client handle.
 *
 * This functions initiates a client SASL authentication.  This
 * function must be called before any other gsasl_client_*() function
 * is called.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_client_start (Gsasl_ctx * ctx,
		    const char *mech, Gsasl_session_ctx ** sctx)
{
  return _gsasl_start (ctx, mech, sctx,
		       ctx->n_client_mechs, ctx->client_mechs, 1);
}

/**
 * gsasl_server_start:
 * @ctx: libgsasl handle.
 * @mech: name of SASL mechanism.
 * @sctx: pointer to server handle.
 *
 * This functions initiates a server SASL authentication.  This
 * function must be called before any other gsasl_server_*() function
 * is called.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_server_start (Gsasl_ctx * ctx,
		    const char *mech, Gsasl_session_ctx ** sctx)
{
  return _gsasl_start (ctx, mech, sctx,
		       ctx->n_server_mechs, ctx->server_mechs, 0);
}
