/* server.c --- SASL mechanism PLAIN as defined in RFC 2595, server side.
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

#include "plain.h"

int
_gsasl_plain_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  return GSASL_OK;
}

int
_gsasl_plain_server_step (Gsasl_session_ctx * sctx,
			  void *mech_data,
			  const char *input,
			  size_t input_len, char *output, size_t * output_len)
{
  Gsasl_server_callback_validate cb_validate;
  Gsasl_server_callback_retrieve cb_retrieve;
  const char *authorization_id = NULL;
  char *authentication_id = NULL;
  char *passwordptr = NULL;
  char *password = NULL;
  Gsasl_ctx *ctx;
  int res;

  *output_len = 0;

  if (input_len == 0)
    return GSASL_NEEDS_MORE;

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

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_validate = gsasl_server_callback_validate_get (ctx);
  cb_retrieve = gsasl_server_callback_retrieve_get (ctx);
  if (cb_validate == NULL && cb_retrieve == NULL)
    return GSASL_NEED_SERVER_VALIDATE_CALLBACK;

  password = malloc (input_len - (passwordptr - input) + 1);
  if (password == NULL)
    return GSASL_MALLOC_ERROR;
  memcpy (password, passwordptr, input_len - (passwordptr - input));
  password[input_len - (passwordptr - input)] = '\0';

  if (cb_validate)
    {
      res = cb_validate (sctx, authorization_id, authentication_id, password);
    }
  else
    {
      size_t keylen;
      char *key;
      char *normkey;

      res = cb_retrieve (sctx, authentication_id, authorization_id, NULL,
			 NULL, &keylen);
      if (res != GSASL_OK)
	{
	  free (password);
	  return res;
	}
      key = malloc (keylen);
      if (key == NULL)
	{
	  free (password);
	  return GSASL_MALLOC_ERROR;
	}
      res = cb_retrieve (sctx, authentication_id, authorization_id, NULL,
			 key, &keylen);
      if (res != GSASL_OK)
	{
	  free (key);
	  free (password);
	  return res;
	}
      normkey = gsasl_stringprep_nfkc (key, keylen);
      free (key);
      if (normkey == NULL)
	{
	  free (normkey);
	  free (password);
	  return GSASL_UNICODE_NORMALIZATION_ERROR;
	}
      if (strlen (password) == strlen (normkey) &&
	  memcmp (normkey, password, strlen (normkey)) == 0)
	res = GSASL_OK;
      else
	res = GSASL_AUTHENTICATION_ERROR;
      free (normkey);
    }
  free (password);

  return res;
}
