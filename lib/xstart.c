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
#ifdef USE_CLIENT
  size_t i;
  int res;

  *sctx = (Gsasl_session_ctx *) malloc (sizeof (**sctx));
  if (*sctx == NULL)
    return GSASL_MALLOC_ERROR;

  memset (*sctx, 0, sizeof (**sctx));

  for (i = 0; i < ctx->n_client_mechs; i++)
    {
      if (mech && strcmp (mech, ctx->client_mechs[i].name) == 0)
	{
	  (*sctx)->mech = &ctx->client_mechs[i];
	  break;
	}
    }

  if ((*sctx)->mech == NULL)
    {
      free (*sctx);
      *sctx = NULL;
      return GSASL_UNKNOWN_MECHANISM;
    }

  (*sctx)->ctx = ctx;
  (*sctx)->clientp = 1;
  (*sctx)->mech_data = NULL;
  res = (*sctx)->mech->client.start (*sctx, &(*sctx)->mech_data);

  if (res != GSASL_OK)
    {
      free (*sctx);
      *sctx = NULL;
      return res;
    }

  return GSASL_OK;
#else
  return GSASL_UNKNOWN_MECHANISM;
#endif
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
#ifdef USE_SERVER
  size_t i;
  int res;

  *sctx = (Gsasl_session_ctx *) malloc (sizeof (**sctx));
  if (*sctx == NULL)
    return GSASL_MALLOC_ERROR;

  memset (*sctx, 0, sizeof (**sctx));

  for (i = 0; i < ctx->n_server_mechs; i++)
    {
      if (mech && strcmp (mech, ctx->server_mechs[i].name) == 0)
	{
	  (*sctx)->mech = &ctx->server_mechs[i];
	  break;
	}
    }

  if ((*sctx)->mech == NULL)
    {
      free (*sctx);
      *sctx = NULL;
      return GSASL_UNKNOWN_MECHANISM;
    }

  (*sctx)->ctx = ctx;
  (*sctx)->clientp = 0;
  (*sctx)->mech_data = NULL;
  res = (*sctx)->mech->server.start (*sctx, &(*sctx)->mech_data);

  if (res != GSASL_OK)
    {
      free (*sctx);
      *sctx = NULL;
      return res;
    }

  return GSASL_OK;
#else
  return GSASL_UNKNOWN_MECHANISM;
#endif
}
