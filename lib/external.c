/* external.c	implementation of SASL mechanism EXTERNAL as defined in RFC2222
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

#ifdef USE_EXTERNAL

int
_gsasl_external_client_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_external_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_external_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  *mech_data = NULL;

  return GSASL_OK;
}

int
_gsasl_external_client_step (Gsasl_session_ctx * sctx,
			     void *mech_data,
			     const char *input,
			     size_t input_len,
			     char *output, size_t * output_len)
{
  *output_len = 0;

  return GSASL_OK;
}

int
_gsasl_external_client_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  return GSASL_OK;
}

/* Server */

int
_gsasl_external_server_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_external_server_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_external_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  Gsasl_ctx *ctx;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_server_callback_external_get (ctx) == NULL)
    return GSASL_NEED_SERVER_EXTERNAL_CALLBACK;

  return GSASL_OK;
}

int
_gsasl_external_server_step (Gsasl_session_ctx * sctx,
			     void *mech_data,
			     const char *input,
			     size_t input_len,
			     char *output, size_t * output_len)
{
  Gsasl_server_callback_external cb_external;
  Gsasl_ctx *ctx;
  int res;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_external = gsasl_server_callback_external_get (ctx);
  if (cb_external == NULL)
    return GSASL_NEED_SERVER_EXTERNAL_CALLBACK;

  res = cb_external (sctx);

  *output_len = 0;

  return res;
}

int
_gsasl_external_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  return GSASL_OK;
}

#endif /* USE_EXTERNAL */
