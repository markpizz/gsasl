/* cram-md5.h --- Implementation of CRAM-MD5 mechanism as defined in RFC 2195.
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

#include "cram-md5.h"

#define MD5LEN 16
#define HEXCHAR(c) ((c & 0x0F) > 9 ? 'a' + (c & 0x0F) - 10 : '0' + (c & 0x0F))
#define DECCHAR(c) ((c & 0x0F) > 9 ? '0' + (c & 0x0F) - 10 : '0' + (c & 0x0F))

#ifdef USE_CLIENT

struct _Gsasl_cram_md5_client_state
{
  int step;
};

int
_gsasl_cram_md5_client_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_cram_md5_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_cram_md5_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  struct _Gsasl_cram_md5_client_state *state;
  Gsasl_ctx *ctx;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

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
_gsasl_cram_md5_client_step (Gsasl_session_ctx * sctx,
			     void *mech_data,
			     const char *input,
			     size_t input_len,
			     char *output, size_t * output_len)
{
  struct _Gsasl_cram_md5_client_state *state = mech_data;
  Gsasl_ctx *ctx;
  Gsasl_client_callback_authentication_id cb_authentication_id;
  Gsasl_client_callback_password cb_password;
  char *hash;
  size_t len;
  char *tmp;
  int i;
  int res;

  switch (state->step)
    {
    case 0:
      state->step++;
      if (input_len == 0)
	{
	  *output_len = 0;
	  return GSASL_NEEDS_MORE;
	}
      /* fall through */

    case 1:
      if (input_len == 0)
	return GSASL_MECHANISM_PARSE_ERROR;

      ctx = gsasl_client_ctx_get (sctx);
      if (ctx == NULL)
	return GSASL_CANNOT_GET_CTX;

      cb_authentication_id =
	gsasl_client_callback_authentication_id_get (ctx);
      if (cb_authentication_id == NULL)
	return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

      cb_password = gsasl_client_callback_password_get (ctx);
      if (cb_password == NULL)
	return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

      /* XXX? password stored in callee's output buffer */
      len = *output_len - 1;
      res = cb_password (sctx, output, &len);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	return res;
      output[len] = '\0';
      tmp = gsasl_stringprep_saslprep (output, NULL);
      if (tmp == NULL)
	return GSASL_SASLPREP_ERROR;
      res = gsasl_hmac_md5 (tmp, strlen (tmp), input, input_len, &hash);
      free (tmp);
      if (res != GSASL_OK)
	return GSASL_CRYPTO_ERROR;

      len = *output_len - 1;
      res = cb_authentication_id (sctx, output, &len);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	return res;
      output[len] = '\0';
      tmp = gsasl_stringprep_saslprep (output, NULL);
      if (tmp == NULL)
	return GSASL_SASLPREP_ERROR;
      if (strlen (tmp) + strlen (" ") + 2 * MD5LEN >= *output_len)
	{
	  free (tmp);
	  return GSASL_TOO_SMALL_BUFFER;
	}
      len = strlen (tmp);
      memcpy (output, tmp, len);
      free (tmp);
      output[len++] = ' ';

      for (i = 0; i < MD5LEN; i++)
	{
	  output[len + 2 * i + 1] = HEXCHAR (hash[i]);
	  output[len + 2 * i + 0] = HEXCHAR (hash[i] >> 4);
	}
      *output_len = len + 2 * MD5LEN;

      free (hash);

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
_gsasl_cram_md5_client_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_cram_md5_client_state *state = mech_data;

  free (state);

  return GSASL_OK;
}

#endif /* USE_CLIENT */

/* Server */

#ifdef USE_SERVER

int
_gsasl_cram_md5_server_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_cram_md5_server_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_cram_md5_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  Gsasl_ctx *ctx;
  char *challenge;
  int i;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_server_callback_cram_md5_get (ctx) == NULL &&
      gsasl_server_callback_retrieve_get (ctx) == NULL)
    return GSASL_NEED_SERVER_CRAM_MD5_CALLBACK;

#define START_OF_XS 1
#define NUMBER_OF_XS 20
  /* Don't leak information in timestamp and hostname fields. */
#define CHALLENGE_FORMAT "<XXXXXXXXXXXXXXXXXXXX.0@josefsson.org>"

  challenge = (char *) malloc (strlen (CHALLENGE_FORMAT) + 1);
  if (challenge == NULL)
    return GSASL_MALLOC_ERROR;

  strcpy (challenge, CHALLENGE_FORMAT);

  gsasl_randomize (0, &challenge[START_OF_XS], NUMBER_OF_XS / 2);

  for (i = 0; i < NUMBER_OF_XS / 2; i++)
    {
      /* The probabilities for each digit are skewed (0-6 more likely
	 than 7-9), but it is just used as a nonce anyway. */
      challenge[START_OF_XS + NUMBER_OF_XS / 2 + i] =
	DECCHAR (challenge[START_OF_XS + i]);
      challenge[START_OF_XS + i] = DECCHAR (challenge[START_OF_XS + i] >> 4);
    }

  *mech_data = challenge;

  return GSASL_OK;
}

int
_gsasl_cram_md5_server_step (Gsasl_session_ctx * sctx,
			     void *mech_data,
			     const char *input,
			     size_t input_len,
			     char *output, size_t * output_len)
{
  char *challenge = mech_data;
  Gsasl_server_callback_cram_md5 cb_cram_md5;
  Gsasl_server_callback_retrieve cb_retrieve;
  char *username = NULL;
  char *key = NULL;
  Gsasl_ctx *ctx;
  int res = GSASL_OK;

  if (input_len == 0)
    {
      if (*output_len < strlen (challenge))
	return GSASL_TOO_SMALL_BUFFER;

      *output_len = strlen (challenge);
      memcpy (output, challenge, *output_len);

      return GSASL_NEEDS_MORE;
    }

  if (input_len <= MD5LEN * 2)
    return GSASL_MECHANISM_PARSE_ERROR;

  if (input[input_len - MD5LEN * 2 - 1] != ' ')
    return GSASL_MECHANISM_PARSE_ERROR;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_cram_md5 = gsasl_server_callback_cram_md5_get (ctx);
  cb_retrieve = gsasl_server_callback_retrieve_get (ctx);
  if (cb_cram_md5 == NULL && cb_retrieve == NULL)
    return GSASL_NEED_SERVER_CRAM_MD5_CALLBACK;

  username = (char *) malloc (input_len);
  if (username == NULL)
    return GSASL_MALLOC_ERROR;

  memcpy (username, input, input_len - MD5LEN * 2);
  username[input_len - MD5LEN * 2 - 1] = '\0';

  if (cb_cram_md5)
    {
      char *response;

      response = (char *) malloc (MD5LEN * 2 + 1);
      if (response == NULL)
	{
	  res = GSASL_MALLOC_ERROR;
	  goto done;
	}

      memcpy (response, input + input_len - MD5LEN * 2, MD5LEN * 2);
      response[MD5LEN * 2 + 1] = '\0';

      res = cb_cram_md5 (sctx, username, challenge, response);

      free (response);
    }
  else if (cb_retrieve)
    {
      char *hash;
      size_t keylen;
      char *normkey;
      int i;

      res = cb_retrieve (sctx, username, NULL, NULL, NULL, &keylen);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	goto done;
      key = malloc (keylen + 1);
      if (key == NULL)
	{
	  res = GSASL_MALLOC_ERROR;
	  goto done;
	}
      res = cb_retrieve (sctx, username, NULL, NULL, key, &keylen);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	goto done;
      key[keylen] = '\0';
      normkey = gsasl_stringprep_saslprep (key, NULL);
      if (normkey == NULL)
	{
	  res = GSASL_SASLPREP_ERROR;
	  goto done;
	}

      res = gsasl_hmac_md5 (normkey, strlen (normkey),
			    challenge, strlen (challenge), &hash);
      free (normkey);
      if (res != GSASL_OK)
	{
	  res = GSASL_CRYPTO_ERROR;
	  goto done;
	}

      res = GSASL_OK;
      for (i = 0; i < MD5LEN; i++)
	if ((input[input_len - MD5LEN * 2 + 2 * i + 1] !=
	     HEXCHAR (hash[i])) ||
	    (input[input_len - MD5LEN * 2 + 2 * i + 0] !=
	     HEXCHAR (hash[i] >> 4)))
	  res = GSASL_AUTHENTICATION_ERROR;

      free (hash);
    }

  free (username);
  if (key)
    free (key);
  *output_len = 0;

done:
  return res;
}

int
_gsasl_cram_md5_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  char *challenge = mech_data;

  free (challenge);

  return GSASL_OK;
}

#endif /* USE_SERVER */
