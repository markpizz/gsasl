/* listmech.c	list active client and server mechanisms
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of libgsasl.
 *
 * Libgsasl is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Libgsasl is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with libgsasl; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

static int
_gsasl_listmech (Gsasl_ctx *ctx,
		 _Gsasl_mechanism *mechs, 
		 size_t n_mechs, 
		 char *out, 
		 size_t *outlen,
		 int clientp)
{
  Gsasl_session_ctx *xctx;
  void *mech_data;
  int i = 0;

  if (out == NULL)
    {
      *outlen = n_mechs * GSASL_MAX_MECHANISM_SIZE;
      return GSASL_OK;
    }

  if (outlen == NULL || *outlen == 0)
    return GSASL_TOO_SMALL_BUFFER;

  *out = '\0';
  for (i = 0; i < n_mechs; i++)
    {
      if ((clientp && 
	   gsasl_client_start (ctx, mechs[i].name, &xctx) == GSASL_OK) ||
	  (!clientp && 
	   gsasl_server_start (ctx, mechs[i].name, &xctx) == GSASL_OK))
	{
	  if (clientp)
	    gsasl_client_finish (xctx);
	  else
	    gsasl_server_finish (xctx);

	  if (strlen(out) + strlen(mechs[i].name) + strlen(" ") >= *outlen)
	    return GSASL_TOO_SMALL_BUFFER;

	  strcat(out, mechs[i].name);
	  strcat(out, " ");
	}
    }

  return GSASL_OK;
}

/**
 * gsasl_client_listmech:
 * @ctx: libgsasl handle.
 * @out: output character array.
 * @outlen: input maximum size of output character array, on output
 * contains actual length of output array.
 * 
 * Write SASL names, separated by space, of mechanisms supported by
 * the libgsasl client to the output array.  To find out how large the
 * output array must be, call this function with out=NULL.
 * 
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_client_listmech (Gsasl_ctx *ctx, char *out, size_t *outlen)
{
  return _gsasl_listmech (ctx, ctx->client_mechs, ctx->n_client_mechs, 
			  out, outlen, 1);
}

/**
 * gsasl_server_listmech:
 * @ctx: libgsasl handle.
 * @out: output character array.
 * @outlen: input maximum size of output character array, on output
 * contains actual length of output array.
 * 
 * Write SASL names, separated by space, of mechanisms supported by
 * the libgsasl server to the output array.  To find out how large the
 * output array must be, call this function with out=NULL.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_server_listmech (Gsasl_ctx *ctx, char *out, size_t *outlen)
{
  return _gsasl_listmech (ctx, ctx->server_mechs, ctx->n_server_mechs, 
			  out, outlen, 0);
}
