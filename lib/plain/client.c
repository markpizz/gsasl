/* client.c --- SASL mechanism PLAIN as defined in RFC 2595, client side.
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
_gsasl_plain_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  return GSASL_OK;
}

int
_gsasl_plain_client_step (Gsasl_session_ctx * sctx,
			  void *mech_data,
			  const char *input, size_t input_len,
			  char **output, size_t * output_len)
{
  char *authzid = NULL, *authid = NULL, *password = NULL;
  size_t authzidlen, authidlen, passwordlen;
  const char *p;
  int res;

  p = gsasl_property_get (sctx, GSASL_CLIENT_AUTHZID);
  if (!p)
    {
      res = GSASL_NO_AUTHZID;
      goto end;
    }

  authzid = gsasl_stringprep_nfkc (p, -1);
  if (authzid == NULL)
    {
      res = GSASL_UNICODE_NORMALIZATION_ERROR;
      goto end;
    }
  authzidlen = strlen (authzid);

  p = gsasl_property_get (sctx, GSASL_CLIENT_AUTHID);
  if (!p)
    {
      res = GSASL_NO_AUTHZID;
      goto end;
    }

  authid = gsasl_stringprep_nfkc (p, -1);
  if (authid == NULL)
    {
      res = GSASL_UNICODE_NORMALIZATION_ERROR;
      goto end;
    }
  authidlen = strlen (authid);

  p = gsasl_property_get (sctx, GSASL_CLIENT_PASSWORD);
  if (!p)
    {
      res = GSASL_NO_AUTHZID;
      goto end;
    }

  password = gsasl_stringprep_nfkc (p, -1);
  if (password == NULL)
    {
      res = GSASL_UNICODE_NORMALIZATION_ERROR;
      goto end;
    }
  passwordlen = strlen (password);

  *output_len = authzidlen + 1 + authidlen + 1 + passwordlen;
  *output = malloc (*output_len);
  if (*output == NULL)
    {
      res = GSASL_MALLOC_ERROR;
      goto end;
    }

  memcpy (*output, authzid, authzidlen);
  (*output)[authzidlen] = '\0';
  memcpy (*output + authzidlen + 1, authid, authidlen);
  (*output)[authzidlen + 1 + authidlen] = '\0';
  memcpy (*output + authzidlen + 1 + authidlen + 1, password, passwordlen);

  res = GSASL_OK;

end:
  if (authzid)
    free (authzid);
  if (authid)
    free (authid);
  if (password)
    free (password);

  return res;
}
