/* xfinish.c	finish libgsasl session
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
 * gsasl_client_finish:
 * @xctx: libgsasl client handle.
 * 
 * Destroy a libgsasl client handle.  The handle must not be used with
 * other libgsasl functions after this call.
 **/
void
gsasl_client_finish (Gsasl_session_ctx *xctx)
{
  xctx->mech->client.finish (xctx, xctx->mech_data);

  free(xctx);
}

/**
 * gsasl_server_finish:
 * @xctx: libgsasl server handle.
 * 
 * Destroy a libgsasl server handle.  The handle must not be used with
 * other libgsasl functions after this call.
 **/
void
gsasl_server_finish (Gsasl_session_ctx *xctx)
{
  xctx->mech->server.finish (xctx, xctx->mech_data);

  free(xctx);
}
