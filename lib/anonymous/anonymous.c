/* anonymous.c	implementation of SASL mechanism ANONYMOUS from RFC 2245
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "anonymous.h"

#ifdef USE_CLIENT

int
_gsasl_anonymous_client_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_anonymous_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_anonymous_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  Gsasl_ctx *ctx;
  int *step;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_client_callback_anonymous_get (ctx) == NULL)
    return GSASL_NEED_SERVER_ANONYMOUS_CALLBACK;

  step = (int *) malloc (sizeof (*step));
  if (step == NULL)
    return GSASL_MALLOC_ERROR;

  *step = 0;

  *mech_data = step;

  return GSASL_OK;
}

int
_gsasl_anonymous_client_step (Gsasl_session_ctx * sctx,
			      void *mech_data,
			      const char *input,
			      size_t input_len,
			      char *output, size_t * output_len)
{
  int *step = mech_data;
  Gsasl_client_callback_anonymous cb_anonymous;
  Gsasl_ctx *ctx;
  int res;

  if (*step > 0)
    return GSASL_OK;

  (*step)++;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_anonymous = gsasl_client_callback_anonymous_get (ctx);
  if (cb_anonymous == NULL)
    return GSASL_NEED_CLIENT_ANONYMOUS_CALLBACK;

  res = cb_anonymous (sctx, output, output_len);
  if (res != GSASL_OK)
    return res;

  return GSASL_OK;
}

int
_gsasl_anonymous_client_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  int *step = mech_data;

  free (step);

  return GSASL_OK;
}

#endif /* USE_CLIENT */

/* Server */

#ifdef USE_SERVER

struct _Gsasl_anonymous_server_state
{
  int step;
};

int
_gsasl_anonymous_server_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_anonymous_server_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_anonymous_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  Gsasl_ctx *ctx;
  struct _Gsasl_anonymous_server_state *state;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_server_callback_anonymous_get (ctx) == NULL)
    return GSASL_NEED_SERVER_ANONYMOUS_CALLBACK;

  state = malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_anonymous_server_step (Gsasl_session_ctx * sctx,
			      void *mech_data,
			      const char *input,
			      size_t input_len,
			      char *output, size_t * output_len)
{
  struct _Gsasl_anonymous_server_state *state = mech_data;
  Gsasl_server_callback_anonymous cb_anonymous;
  Gsasl_ctx *ctx;
  char *token;
  int res;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_anonymous = gsasl_server_callback_anonymous_get (ctx);
  if (cb_anonymous == NULL)
    return GSASL_NEED_SERVER_ANONYMOUS_CALLBACK;

  *output_len = 0;

  switch (state->step)
    {
    case 0:
      state->step++;
      if (input_len == 0)
	return GSASL_NEEDS_MORE;
      /* fall through */

    case 1:
      if (input_len == 0)
	return GSASL_MECHANISM_PARSE_ERROR;

      token = malloc (input_len + 1);
      if (token == NULL)
	return GSASL_MALLOC_ERROR;

      memcpy (token, input, input_len);
      token[input_len] = '\0';

      res = cb_anonymous (sctx, token);

      free (token);

      state->step++;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

int
_gsasl_anonymous_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_anonymous_server_state *state = mech_data;

  free (state);

  return GSASL_OK;
}

#endif /* USE_SERVER */
