/* done.c	exit point for libgsasl
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

/**
 * gsasl_done:
 * @ctx: libgsasl handle.
 * 
 * This function destroys a libgsasl handle.  The handle must not be
 * used with other libgsasl functions after this call.
 **/
void
gsasl_done (Gsasl_ctx * ctx)
{
  int i;

  if (ctx == NULL)
    return;

  for (i = 0; i < ctx->n_client_mechs; i++)
    ctx->client_mechs[i].client.done (ctx);

  for (i = 0; i < ctx->n_server_mechs; i++)
    ctx->server_mechs[i].server.done (ctx);

  if (ctx->client_mechs)
    free (ctx->client_mechs);

  if (ctx->server_mechs)
    free (ctx->server_mechs);

  free (ctx);

  return;
}
