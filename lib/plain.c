/* plain.c	implementation of SASL mechanism PLAIN as defined in RFC 2595
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

#ifdef USE_PLAIN

struct _Gsasl_plain_client_state
{
  int step;
};

int
_gsasl_plain_client_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_plain_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_plain_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  struct _Gsasl_plain_client_state *state;
  Gsasl_ctx *ctx;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_client_callback_authorization_id_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK;

  if (gsasl_client_callback_authentication_id_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

  if (gsasl_client_callback_password_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  state = malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_plain_client_step (Gsasl_session_ctx * sctx,
			  void *mech_data,
			  const char *input,
			  size_t input_len, char *output, size_t * output_len)
{
  struct _Gsasl_plain_client_state *state = mech_data;
  Gsasl_client_callback_authentication_id cb_authentication_id;
  Gsasl_client_callback_authorization_id cb_authorization_id;
  Gsasl_client_callback_password cb_password;
  Gsasl_ctx *ctx;
  char *tmp, *tmp2;
  size_t len;
  int res;

  switch (state->step)
    {
    case 0:
      ctx = gsasl_client_ctx_get (sctx);
      if (ctx == NULL)
	return GSASL_CANNOT_GET_CTX;

      cb_authorization_id = gsasl_client_callback_authorization_id_get (ctx);
      if (cb_authorization_id == NULL)
	return GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK;

      cb_authentication_id =
	gsasl_client_callback_authentication_id_get (ctx);
      if (cb_authentication_id == NULL)
	return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

      cb_password = gsasl_client_callback_password_get (ctx);
      if (cb_password == NULL)
	return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

      tmp = output;

      len = *output_len - (tmp - output);
      res = cb_authorization_id (sctx, tmp, &len);
      if (res != GSASL_OK)
	return res;
      tmp2 = stringprep_utf8_nfkc_normalize (tmp, len);
      if (tmp2 == NULL)
	return GSASL_UNICODE_NORMALIZATION_ERROR;
      if (*output_len <= tmp - output + strlen (tmp2))
	return GSASL_TOO_SMALL_BUFFER;
      memcpy (tmp, tmp2, strlen (tmp2));
      tmp += strlen (tmp2);
      free (tmp2);
      *tmp++ = '\0';

      len = *output_len - (tmp - output);
      res = cb_authentication_id (sctx, tmp, &len);
      if (res != GSASL_OK)
	return res;
      tmp2 = stringprep_utf8_nfkc_normalize (tmp, len);
      if (tmp2 == NULL)
	return GSASL_UNICODE_NORMALIZATION_ERROR;
      if (*output_len <= tmp - output + strlen (tmp2))
	return GSASL_TOO_SMALL_BUFFER;
      memcpy (tmp, tmp2, strlen (tmp2));
      tmp += strlen (tmp2);
      free (tmp2);
      *tmp++ = '\0';

      len = *output_len - (tmp - output);
      res = cb_password (sctx, tmp, &len);
      if (res != GSASL_OK)
	return res;
      tmp2 = stringprep_utf8_nfkc_normalize (tmp, len);
      if (tmp2 == NULL)
	return GSASL_UNICODE_NORMALIZATION_ERROR;
      if (*output_len <= tmp - output + strlen (tmp2))
	return GSASL_TOO_SMALL_BUFFER;
      memcpy (tmp, tmp2, strlen (tmp2));
      tmp += strlen (tmp2);
      free (tmp2);

      *output_len = tmp - output;

      state->step++;
      res = GSASL_OK;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

int
_gsasl_plain_client_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_plain_client_state *state = mech_data;

  free (state);

  return GSASL_OK;
}

/* Server */

struct _Gsasl_plain_server_state
{
  int step;
};

int
_gsasl_plain_server_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_plain_server_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_plain_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  Gsasl_ctx *ctx;
  struct _Gsasl_plain_server_state *state;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_server_callback_validate_get (ctx) == NULL &&
      gsasl_server_callback_retrieve_get (ctx) == NULL)
    return GSASL_NEED_SERVER_VALIDATE_CALLBACK;

  state = malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_plain_server_step (Gsasl_session_ctx * sctx,
			  void *mech_data,
			  const char *input,
			  size_t input_len, char *output, size_t * output_len)
{
  struct _Gsasl_plain_server_state *state = mech_data;
  Gsasl_server_callback_validate cb_validate;
  Gsasl_server_callback_retrieve cb_retrieve;
  const char *authorization_id = NULL;
  char *authentication_id = NULL;
  char *passwordptr = NULL;
  char *password = NULL;
  Gsasl_ctx *ctx;
  int res;

  *output_len = 0;

  switch (state->step)
    {
    case 0:
      state->step++;
      if (input_len == 0)
	return GSASL_NEEDS_MORE;
      /* fall through */

    case 1:
      authorization_id = input;
      authentication_id = memchr (input, 0, input_len);
      if (authentication_id)
	{
	  authentication_id++;
	  passwordptr = memchr (authentication_id, 0,
				input_len - strlen (authorization_id) - 1);
	  if (passwordptr != NULL)
	    passwordptr++;
	}

      if (passwordptr == NULL)
	return GSASL_MECHANISM_PARSE_ERROR;

      password = malloc (input_len - (passwordptr - input) + 1);
      if (password == NULL)
	return GSASL_MALLOC_ERROR;
      memcpy (password, passwordptr, input_len - (passwordptr - input));
      password[input_len - (passwordptr - input)] = '\0';

      ctx = gsasl_server_ctx_get (sctx);
      if (ctx == NULL)
	return GSASL_CANNOT_GET_CTX;

      cb_validate = gsasl_server_callback_validate_get (ctx);
      cb_retrieve = gsasl_server_callback_retrieve_get (ctx);
      if (cb_validate == NULL && cb_retrieve == NULL)
	return GSASL_NEED_SERVER_VALIDATE_CALLBACK;

      if (cb_validate)
	{
	  res = cb_validate (sctx, authorization_id, authentication_id,
			     password);
	}
      else
	{
	  size_t keylen;
	  char *key;
	  char *normkey;

	  res = cb_retrieve (sctx, authentication_id, authorization_id, NULL,
			     NULL, &keylen);
	  if (res != GSASL_OK)
	    return res;
	  key = malloc (keylen);
	  if (key == NULL)
	    return GSASL_MALLOC_ERROR;
	  res = cb_retrieve (sctx, authentication_id, authorization_id, NULL,
			     key, &keylen);
	  if (res != GSASL_OK)
	    {
	      free (key);
	      return res;
	    }
	  normkey = stringprep_utf8_nfkc_normalize (key, keylen);
	  free (key);
	  if (normkey == NULL)
	    {
	      free (normkey);
	      return GSASL_UNICODE_NORMALIZATION_ERROR;
	    }
	  if (strlen (password) == strlen (normkey) &&
	      memcmp (normkey, password, strlen (normkey)) == 0)
	    res = GSASL_OK;
	  else
	    res = GSASL_AUTHENTICATION_ERROR;
	  free (normkey);
	}
      state->step++;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

int
_gsasl_plain_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_plain_server_state *state = mech_data;

  free (state);

  return GSASL_OK;
}

#endif /* USE_PLAIN */
