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

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "cram-md5.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

/* Get cram_md5_digest. */
#include "digest.h"

int
_gsasl_cram_md5_client_step (Gsasl_session_ctx * sctx,
			     void *mech_data,
			     const char *input, size_t input_len,
			     char **output, size_t * output_len)
{
  char response[CRAM_MD5_DIGEST_LEN];
  const char *p;
  size_t len;
  char *tmp;

  if (input_len == 0)
    {
      *output_len = 0;
      *output = NULL;
      return GSASL_NEEDS_MORE;
    }

  p = gsasl_property_get (sctx, GSASL_PASSWORD);
  if (!p)
    return GSASL_NO_PASSWORD;

  tmp = gsasl_stringprep_saslprep (p, NULL);
  if (tmp == NULL)
    return GSASL_SASLPREP_ERROR;

  cram_md5_digest (input, input_len, tmp, strlen (tmp), response);

  free (tmp);

  p = gsasl_property_get (sctx, GSASL_AUTHID);
  if (!p)
    return GSASL_NO_AUTHID;

  tmp = gsasl_stringprep_saslprep (p, NULL);
  if (tmp == NULL)
    return GSASL_SASLPREP_ERROR;

  len = strlen (tmp);

  *output_len = len + strlen (" ") + CRAM_MD5_DIGEST_LEN;
  *output = malloc (*output_len);
  if (!*output)
    {
      free (tmp);
      return GSASL_MALLOC_ERROR;
    }

  memcpy (*output, tmp, len);
  (*output)[len++] = ' ';
  memcpy (*output + len, response, CRAM_MD5_DIGEST_LEN);

  free (tmp);

  return GSASL_OK;
}
