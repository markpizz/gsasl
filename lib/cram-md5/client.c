/* client.c --- SASL CRAM-MD5 client side functions.
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
_gsasl_cram_md5_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  Gsasl_ctx *ctx;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_client_callback_authentication_id_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

  if (gsasl_client_callback_password_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  return GSASL_OK;
}

int
_gsasl_cram_md5_client_step (Gsasl_session_ctx * sctx,
			     void *mech_data,
			     const char *input,
			     size_t input_len,
			     char *output, size_t * output_len)
{
  Gsasl_ctx *ctx;
  Gsasl_client_callback_authentication_id cb_authentication_id;
  Gsasl_client_callback_password cb_password;
  char *hash;
  size_t len;
  char *tmp;
  int i;
  int res;

  if (input_len == 0)
    {
      *output_len = 0;
      return GSASL_NEEDS_MORE;
    }

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

  return GSASL_OK;
}
