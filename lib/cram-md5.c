/* cram-md5.c	implementation of SASL mechanism CRAM-MD5 from RFC 2195
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

#ifdef USE_CRAM_MD5

#include <gcrypt.h>

struct _Gsasl_cram_md5_client_state
{
  int step;
};

int
_gsasl_cram_md5_client_init (Gsasl_ctx * ctx)
{
  int res;

  if (gcry_check_version (GCRYPT_VERSION) == NULL)
    return GSASL_GCRYPT_ERROR;

  res = gcry_control (GCRYCTL_INIT_SECMEM, 512, 0);
  if (res != GCRYERR_SUCCESS)
    return GSASL_GCRYPT_ERROR;

  return GSASL_OK;
}

void
_gsasl_cram_md5_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_cram_md5_client_start (Gsasl_session_ctx * cctx, void **mech_data)
{
  struct _Gsasl_cram_md5_client_state *state;
  Gsasl_ctx *ctx;

  ctx = gsasl_client_ctx_get (cctx);
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
_gsasl_cram_md5_client_step (Gsasl_session_ctx * cctx,
			     void *mech_data,
			     const char *input,
			     size_t input_len,
			     char *output, size_t * output_len)
{
  struct _Gsasl_cram_md5_client_state *state = mech_data;
  Gsasl_ctx *ctx;
  Gsasl_client_callback_authentication_id cb_authentication_id;
  Gsasl_client_callback_password cb_password;
  GCRY_MD_HD md5h;
  unsigned char *hash;
  int hash_len = gcry_md_get_algo_dlen (GCRY_MD_MD5);
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

      ctx = gsasl_client_ctx_get (cctx);
      if (ctx == NULL)
	return GSASL_CANNOT_GET_CTX;

      cb_authentication_id =
	gsasl_client_callback_authentication_id_get (ctx);
      if (cb_authentication_id == NULL)
	return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

      cb_password = gsasl_client_callback_password_get (ctx);
      if (cb_password == NULL)
	return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

      md5h =
	gcry_md_open (GCRY_MD_MD5, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
      if (md5h == NULL)
	return GSASL_GCRYPT_ERROR;

      /* XXX? password stored in callee's output buffer */
      len = *output_len;
      res = cb_password (cctx, output, &len);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	return res;
      tmp = stringprep_utf8_nfkc_normalize (output, len);
      if (tmp == NULL)
	return GSASL_UNICODE_NORMALIZATION_ERROR;
      res = gcry_md_setkey (md5h, tmp, strlen (tmp));
      free (tmp);
      if (res != GCRYERR_SUCCESS)
	return GSASL_GCRYPT_ERROR;

      gcry_md_write (md5h, /*XXX*/ (unsigned char *) input, input_len);

      hash = gcry_md_read (md5h, GCRY_MD_MD5);
      if (hash == NULL)
	return GSASL_GCRYPT_ERROR;

      len = *output_len;
      res = cb_authentication_id (cctx, output, &len);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	return res;
      tmp = stringprep_utf8_nfkc_normalize (output, len);
      if (tmp == NULL)
	return GSASL_UNICODE_NORMALIZATION_ERROR;
      if (strlen (tmp) + strlen (" ") + 2 * hash_len >= *output_len)
	{
	  free (tmp);
	  return GSASL_TOO_SMALL_BUFFER;
	}
      len = strlen (tmp);
      memcpy (output, tmp, len);
      free (tmp);
      output[len++] = ' ';

      for (i = 0; i < hash_len; i++)
	{
	  output[len + 2 * i + 1] = HEXCHAR (hash[i]);
	  output[len + 2 * i + 0] = HEXCHAR (hash[i] >> 4);
	}
      *output_len = len + 2 * hash_len;

      gcry_md_close (md5h);

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
_gsasl_cram_md5_client_finish (Gsasl_session_ctx * cctx, void *mech_data)
{
  struct _Gsasl_cram_md5_client_state *state = mech_data;

  free (state);

  return GSASL_OK;
}

/* Server */

int
_gsasl_cram_md5_server_init (Gsasl_ctx * ctx)
{
  if (gcry_check_version (GCRYPT_VERSION) == NULL)
    return GSASL_GCRYPT_ERROR;

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

  /* XXX this is ad-hoc and uses "localhost" instead of FQDN */

#define START_OF_XS 1
#define NUMBER_OF_XS 16
#define CHALLENGE_FORMAT "<XXXXXXXXXXXXXXXX.libgsasl@localhost>"

  challenge = (char *) malloc (strlen (CHALLENGE_FORMAT) + 1);
  if (challenge == NULL)
    return GSASL_MALLOC_ERROR;

  strcpy (challenge, CHALLENGE_FORMAT);

  gcry_randomize ((unsigned char *) challenge + 1,
		  NUMBER_OF_XS, GCRY_WEAK_RANDOM);

  for (i = 0; i < NUMBER_OF_XS / 2; i++)
    {
      challenge[START_OF_XS + NUMBER_OF_XS / 2 + i] =
	HEXCHAR (challenge[START_OF_XS + i]);
      challenge[START_OF_XS + i] = HEXCHAR (challenge[START_OF_XS + i] >> 4);
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
  int hash_len = gcry_md_get_algo_dlen (GCRY_MD_MD5);
  char *username = NULL;
  char *key = NULL;
  Gsasl_ctx *ctx;
  int res;

  if (input_len == 0)
    {
      if (*output_len < strlen (challenge))
	return GSASL_TOO_SMALL_BUFFER;

      *output_len = strlen (challenge);
      memcpy (output, challenge, *output_len);

      return GSASL_NEEDS_MORE;
    }

  if (input_len <= hash_len * 2)
    return GSASL_MECHANISM_PARSE_ERROR;

  if (input[input_len - hash_len * 2 - 1] != ' ')
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

  memcpy (username, input, input_len - hash_len * 2);
  username[input_len - hash_len * 2 - 1] = '\0';

  if (cb_cram_md5)
    {
      char *response;

      response = (char *) malloc (hash_len * 2 + 1);
      if (response == NULL)
	{
	  res = GSASL_MALLOC_ERROR;
	  goto done;
	}

      memcpy (response, input + input_len - hash_len * 2, hash_len * 2);
      response[hash_len * 2 + 1] = '\0';

      res = cb_cram_md5 (sctx, username, challenge, response);

      free (response);
    }
  else if (cb_retrieve)
    {
      GCRY_MD_HD md5h;
      unsigned char *hash;
      size_t keylen;
      char *normkey;
      int i;

      md5h =
	gcry_md_open (GCRY_MD_MD5, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
      if (md5h == NULL)
	{
	  res = GSASL_GCRYPT_ERROR;
	  goto done;
	}

      res = cb_retrieve (sctx, username, NULL, NULL, NULL, &keylen);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	goto done;
      key = malloc (keylen);
      if (key == NULL)
	{
	  res = GSASL_MALLOC_ERROR;
	  goto done;
	}
      res = cb_retrieve (sctx, username, NULL, NULL, key, &keylen);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	goto done;
      normkey = stringprep_utf8_nfkc_normalize (key, keylen);
      if (normkey == NULL)
	{
	  res = GSASL_UNICODE_NORMALIZATION_ERROR;
	  goto done;
	}

      res = gcry_md_setkey (md5h, normkey, strlen (normkey));
      free (normkey);
      if (res != GCRYERR_SUCCESS)
	{
	  res = GSASL_GCRYPT_ERROR;
	  goto done;
	}

      gcry_md_write (md5h, /*XXX*/ (unsigned char *)challenge,
		     strlen (challenge));

      hash = gcry_md_read (md5h, GCRY_MD_MD5);
      if (hash == NULL)
	{
	  res = GSASL_GCRYPT_ERROR;
	  goto done;
	}

      res = GSASL_OK;
      for (i = 0; i < hash_len; i++)
	if ((input[input_len - hash_len * 2 + 2 * i + 1] != HEXCHAR (hash[i]))
	    || (input[input_len - hash_len * 2 + 2 * i + 0] !=
		HEXCHAR (hash[i] >> 4)))
	  res = GSASL_AUTHENTICATION_ERROR;
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

#endif /* USE_CRAM_MD5 */
