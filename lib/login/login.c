/* login.h --- Implementation of non-standard SASL mechanism LOGIN.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#include "login.h"

#ifdef USE_CLIENT

struct _Gsasl_login_client_state
{
  int step;
};

int
_gsasl_login_client_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_login_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_login_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  struct _Gsasl_login_client_state *state;
  Gsasl_ctx *ctx;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_client_callback_authorization_id_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK;

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
_gsasl_login_client_step (Gsasl_session_ctx * sctx,
			  void *mech_data,
			  const char *input,
			  size_t input_len, char *output, size_t * output_len)
{
  struct _Gsasl_login_client_state *state = mech_data;
  Gsasl_client_callback_authorization_id cb_authorization_id;
  Gsasl_client_callback_password cb_password;
  Gsasl_ctx *ctx;
  char *tmp;
  int res;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_authorization_id = gsasl_client_callback_authorization_id_get (ctx);
  if (cb_authorization_id == NULL)
    return GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK;

  cb_password = gsasl_client_callback_password_get (ctx);
  if (cb_password == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  switch (state->step)
    {
    case 0:
      res = cb_authorization_id (sctx, output, output_len);
      if (res != GSASL_OK)
	return res;
      tmp = gsasl_stringprep_nfkc (output, *output_len);
      if (tmp == NULL)
	return GSASL_UNICODE_NORMALIZATION_ERROR;
      if (*output_len < strlen (tmp))
	return GSASL_TOO_SMALL_BUFFER;
      memcpy (output, tmp, strlen (tmp));
      *output_len = strlen (tmp);
      free (tmp);
      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 1:
      res = cb_password (sctx, output, output_len);
      if (res != GSASL_OK)
	return res;
      tmp = gsasl_stringprep_nfkc (output, *output_len);
      if (tmp == NULL)
	return GSASL_UNICODE_NORMALIZATION_ERROR;
      if (*output_len < strlen (tmp))
	return GSASL_TOO_SMALL_BUFFER;
      memcpy (output, tmp, strlen (tmp));
      *output_len = strlen (tmp);
      free (tmp);
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
_gsasl_login_client_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_login_client_state *state = mech_data;

  free (state);

  return GSASL_OK;
}
#endif

/* Server */

#ifdef USE_SERVER

struct _Gsasl_login_server_state
{
  int step;
  char *username;
};

#define CHALLENGE_USERNAME "User Name"
#define CHALLENGE_PASSWORD "Password"

int
_gsasl_login_server_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_login_server_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_login_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  struct _Gsasl_login_server_state *state;
  Gsasl_ctx *ctx;

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
  state->username = NULL;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_login_server_step (Gsasl_session_ctx * sctx,
			  void *mech_data,
			  const char *input,
			  size_t input_len, char *output, size_t * output_len)
{
  struct _Gsasl_login_server_state *state = mech_data;
  Gsasl_server_callback_validate cb_validate;
  Gsasl_server_callback_retrieve cb_retrieve;
  Gsasl_ctx *ctx;
  char *password;
  int res;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_validate = gsasl_server_callback_validate_get (ctx);
  cb_retrieve = gsasl_server_callback_retrieve_get (ctx);
  if (cb_validate == NULL && cb_retrieve == NULL)
    return GSASL_NEED_SERVER_VALIDATE_CALLBACK;

  switch (state->step)
    {
    case 0:
      if (*output_len < strlen (CHALLENGE_USERNAME))
	return GSASL_TOO_SMALL_BUFFER;

      memcpy (output, CHALLENGE_USERNAME, strlen (CHALLENGE_USERNAME));
      *output_len = strlen (CHALLENGE_USERNAME);

      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 1:
      if (input_len == 0)
	return GSASL_MECHANISM_PARSE_ERROR;

      if (*output_len < strlen (CHALLENGE_PASSWORD))
	return GSASL_TOO_SMALL_BUFFER;

      state->username = malloc (input_len + 1);
      if (state->username == NULL)
	return GSASL_MALLOC_ERROR;

      memcpy (state->username, input, input_len);
      state->username[input_len] = '\0';

      memcpy (output, CHALLENGE_PASSWORD, strlen (CHALLENGE_PASSWORD));
      *output_len = strlen (CHALLENGE_PASSWORD);

      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 2:
      if (input_len == 0)
	return GSASL_MECHANISM_PARSE_ERROR;

      password = malloc (input_len + 1);
      if (password == NULL)
	return GSASL_MALLOC_ERROR;

      memcpy (password, input, input_len);
      password[input_len] = '\0';

      if (cb_validate)
	{
	  res = cb_validate (sctx, state->username, NULL, password);
	}
      else
	{
	  size_t keylen;
	  char *key;
	  char *normkey;

	  res =
	    cb_retrieve (sctx, state->username, NULL, NULL, NULL, &keylen);
	  if (res != GSASL_OK)
	    return res;
	  key = malloc (keylen);
	  if (key == NULL)
	    return GSASL_MALLOC_ERROR;
	  res = cb_retrieve (sctx, state->username, NULL, NULL, key, &keylen);
	  if (res != GSASL_OK)
	    {
	      free (key);
	      return res;
	    }
	  normkey = gsasl_stringprep_nfkc (key, keylen);
	  free (key);
	  if (normkey == NULL)
	    return GSASL_UNICODE_NORMALIZATION_ERROR;
	  if (strlen (password) == strlen (normkey) &&
	      memcmp (normkey, password, strlen (normkey)) == 0)
	    res = GSASL_OK;
	  else
	    res = GSASL_AUTHENTICATION_ERROR;
	  free (normkey);
	}

      free (password);

      *output_len = 0;
      state->step++;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

int
_gsasl_login_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_login_server_state *state = mech_data;

  if (state->username)
    free (state->username);
  free (state);

  return GSASL_OK;
}

#endif /* USE_SERVER */
