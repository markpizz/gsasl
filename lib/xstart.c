/* xstart.c	start libgsasl session
 * Copyright (C) 2002  Simon Josefsson
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

static int
_gsasl_session_start (Gsasl_ctx * ctx,
		      const char *mech,
		      Gsasl_session_ctx ** xctx, int clientp)
{
  int i = 0;
  int res;

  *xctx = (Gsasl_session_ctx *) malloc (sizeof (**xctx));
  if (*xctx == NULL)
    return GSASL_MALLOC_ERROR;

  memset (*xctx, 0, sizeof (**xctx));

  for (i = 0; i < (clientp ? ctx->n_client_mechs : ctx->n_server_mechs); i++)
    {
      if (mech
	  && ((clientp && strcmp (mech, ctx->client_mechs[i].name) == 0)
	      || (!clientp && strcmp (mech, ctx->server_mechs[i].name) == 0)))
	{
	  if (clientp)
	    (*xctx)->mech = &ctx->client_mechs[i];
	  else
	    (*xctx)->mech = &ctx->server_mechs[i];
	  break;
	}
    }

  if ((*xctx)->mech == NULL)
    {
      free (*xctx);
      *xctx = NULL;
      return GSASL_UNKNOWN_MECHANISM;
    }

  (*xctx)->ctx = ctx;
  (*xctx)->clientp = clientp;
  (*xctx)->mech_data = NULL;
  if (clientp)
    res = (*xctx)->mech->client.start (*xctx, &(*xctx)->mech_data);
  else
    res = (*xctx)->mech->server.start (*xctx, &(*xctx)->mech_data);

  if (res != GSASL_OK)
    {
      free (*xctx);
      *xctx = NULL;
      return res;
    }

  return GSASL_OK;
}

/**
 * gsasl_client_start:
 * @ctx: libgsasl handle.
 * @mech: name of SASL mechanism.
 * @xctx: pointer to client handle.
 * 
 * This functions initiates a client SASL authentication.  This
 * function must be called before any other gsasl_client_*() function
 * is called.  
 * 
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_client_start (Gsasl_ctx * ctx,
		    const char *mech, Gsasl_session_ctx ** xctx)
{
  return _gsasl_session_start (ctx, mech, xctx, 1);
}

/**
 * gsasl_server_start:
 * @ctx: libgsasl handle.
 * @mech: name of SASL mechanism.
 * @xctx: pointer to server handle.
 * 
 * This functions initiates a server SASL authentication.  This
 * function must be called before any other gsasl_server_*() function
 * is called.  
 * 
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_server_start (Gsasl_ctx * ctx,
		    const char *mech, Gsasl_session_ctx ** xctx)
{
  return _gsasl_session_start (ctx, mech, xctx, 0);
}
