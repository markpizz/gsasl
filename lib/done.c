/* done.c	exit point for libgsasl
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
 * gsasl_done:
 * @ctx: libgsasl handle.
 *
 * This function destroys a libgsasl handle.  The handle must not be
 * used with other libgsasl functions after this call.
 **/
void
gsasl_done (Gsasl * ctx)
{
  size_t i;

  if (!VALID_HANDLE (ctx))
    return;

#ifdef USE_CLIENT
  for (i = 0; i < ctx->n_client_mechs; i++)
    ctx->client_mechs[i].client.done (ctx);

  if (ctx->client_mechs)
    free (ctx->client_mechs);
#endif

#ifdef USE_SERVER
  for (i = 0; i < ctx->n_server_mechs; i++)
    ctx->server_mechs[i].server.done (ctx);

  if (ctx->server_mechs)
    free (ctx->server_mechs);
#endif

  free (ctx);

  return;
}
