/* anonymous.c	implementation of SASL mechanism ANONYMOUS from RFC 2245
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

#ifdef USE_ANONYMOUS

int
_gsasl_anonymous_client_init (Gsasl_ctx *ctx)
{
  return GSASL_OK;
}

void
_gsasl_anonymous_client_done (Gsasl_ctx *ctx)
{
  return;
}

int
_gsasl_anonymous_client_start (Gsasl_session_ctx *cctx, 
			       void **mech_data)
{
  Gsasl_ctx *ctx;
  int *step;

  ctx = gsasl_client_ctx_get (cctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_client_callback_anonymous_get (ctx) == NULL)
    return GSASL_NEED_SERVER_ANONYMOUS_CALLBACK;

  step = (int*) malloc(sizeof(*step));
  if (step == NULL)
    return GSASL_MALLOC_ERROR;

  *step = 0;

  *mech_data = step;
  
  return GSASL_OK;
}

int
_gsasl_anonymous_client_step  (Gsasl_session_ctx *cctx, 
			       void *mech_data, 
			       const char *input,
			       size_t input_len,
			       char *output,
			       size_t *output_len)
{
  int *step = mech_data;
  Gsasl_client_callback_anonymous cb_anonymous;
  Gsasl_ctx *ctx;
  int res;

  if (*step > 0)
    return GSASL_OK;

  (*step)++;

  ctx = gsasl_client_ctx_get (cctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_anonymous = gsasl_client_callback_anonymous_get (ctx);
  if (cb_anonymous == NULL)
    return GSASL_NEED_SERVER_ANONYMOUS_CALLBACK;

  res = cb_anonymous (cctx, output, output_len);
  if (res != GSASL_OK)
      return res;

  *output_len = strlen(output);

  return GSASL_NEEDS_MORE;
}

int
_gsasl_anonymous_client_finish (Gsasl_session_ctx *cctx,
				void *mech_data)
{
  int *step = mech_data;

  free(step);

  return GSASL_OK;
}

/* Server */

int
_gsasl_anonymous_server_init (Gsasl_ctx *ctx)
{
  return GSASL_OK;
}

void
_gsasl_anonymous_server_done (Gsasl_ctx *ctx)
{
  return;
}

int
_gsasl_anonymous_server_start (Gsasl_session_ctx *sctx, 
			       void **mech_data)
{
  Gsasl_ctx *ctx;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_server_callback_anonymous_get (ctx) == NULL)
    return GSASL_NEED_SERVER_ANONYMOUS_CALLBACK;

  return GSASL_OK;
}

int
_gsasl_anonymous_server_step (Gsasl_session_ctx *sctx, 
			      void *mech_data, 
			      const char *input,
			      size_t input_len,
			      char *output,
			      size_t *output_len)
{
  Gsasl_server_callback_anonymous cb_anonymous;
  Gsasl_ctx *ctx;
  char *token;
  int res;

  if (input_len == 0)
    {
      *output_len = 0;
      return GSASL_NEEDS_MORE;
    }

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_anonymous = gsasl_server_callback_anonymous_get (ctx);
  if (cb_anonymous == NULL)
    return GSASL_NEED_SERVER_ANONYMOUS_CALLBACK;

  token = malloc(input_len + 1);
  if (token == NULL)
    return GSASL_MALLOC_ERROR;

  memcpy(token, input, input_len);
  token[input_len] = '\0';

  res = cb_anonymous(sctx, token);

  free(token);

  return res;
}

int
_gsasl_anonymous_server_finish (Gsasl_session_ctx *sctx, 
				void *mech_data)
{
  return GSASL_OK;
}

#endif /* USE_ANONYMOUS */
