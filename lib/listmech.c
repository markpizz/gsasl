/* listmech.c	list active client and server mechanisms
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

static int
_gsasl_listmech (Gsasl_ctx * ctx,
		 _Gsasl_mechanism * mechs,
		 size_t n_mechs, char **out, int clientp)
{
  Gsasl_session_ctx *sctx;
  char *list;
  size_t i;
  int rc;

  list = malloc (n_mechs * (GSASL_MAX_MECHANISM_SIZE + 1));
  if (!list)
    return GSASL_MALLOC_ERROR;

  *list = '\0';
  for (i = 0; i < n_mechs; i++)
    {
      if (clientp)
	rc = gsasl_client_start (ctx, mechs[i].name, &sctx);
      else
	rc = gsasl_server_start (ctx, mechs[i].name, &sctx);

      if (rc == GSASL_OK)
	{
	  if (clientp)
	    gsasl_client_finish (sctx);
	  else
	    gsasl_server_finish (sctx);

	  strcat (list, mechs[i].name);
	  if (i < n_mechs - 1)
	    strcat (list, " ");
	}
    }

  *out = list;

  return GSASL_OK;
}

/**
 * gsasl_client_mechlist:
 * @ctx: libgsasl handle.
 * @out: newly allocated output character array.
 *
 * Return a newly allocated string containing SASL names, separated by
 * space, of mechanisms supported by the libgsasl client.  @out is
 * allocated by this function, and it is the responsibility of caller
 * to deallocate it.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_client_mechlist (Gsasl_ctx * ctx, char **out)
{
  return _gsasl_listmech (ctx, ctx->client_mechs, ctx->n_client_mechs,
			  out, 1);
}

/**
 * gsasl_server_listmech:
 * @ctx: libgsasl handle.
 * @out: newly allocated output character array.
 *
 * Return a newly allocated string containing SASL names, separated by
 * space, of mechanisms supported by the libgsasl server.  @out is
 * allocated by this function, and it is the responsibility of caller
 * to deallocate it.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_server_mechlist (Gsasl_ctx * ctx, char **out)
{
  return _gsasl_listmech (ctx, ctx->server_mechs, ctx->n_server_mechs,
			  out, 0);
}
