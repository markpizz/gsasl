/* server.c --- SASL CRAM-MD5 server side functions.
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

/* Get cram_md5_challenge. */
#include "challenge.h"

#define MD5LEN 16
#define HEXCHAR(c) ((c & 0x0F) > 9 ? 'a' + (c & 0x0F) - 10 : '0' + (c & 0x0F))

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

  challenge = malloc (CRAM_MD5_CHALLENGE_LEN);
  if (challenge == NULL)
    return GSASL_MALLOC_ERROR;

  cram_md5_challenge (challenge);

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
