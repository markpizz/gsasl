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

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "plain.h"

/* Get memcpy, memchr, strlen. */
#include <string.h>

/* Get malloc, free. */
#include <stdlib.h>

int
_gsasl_plain_server_step (Gsasl_session * sctx,
			  void *mech_data,
			  const char *input, size_t input_len,
			  char **output, size_t * output_len)
{
  const char *authorization_id = NULL;
  char *authentication_id = NULL;
  char *passwordptr = NULL;
  char *password = NULL;
  int res;

  *output_len = 0;
  *output = NULL;

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

  password = malloc (input_len - (passwordptr - input) + 1);
  if (password == NULL)
    return GSASL_MALLOC_ERROR;
  memcpy (password, passwordptr, input_len - (passwordptr - input));
  password[input_len - (passwordptr - input)] = '\0';

  if (input_len - (passwordptr - input) != strlen (password))
    {
      free (password);
      return GSASL_MECHANISM_PARSE_ERROR;
    }

  gsasl_property_set (sctx, GSASL_AUTHID, authentication_id);
  gsasl_property_set (sctx, GSASL_AUTHZID, authorization_id);
  gsasl_property_set (sctx, GSASL_PASSWORD, password);

  res = gsasl_callback (NULL, sctx, GSASL_VALIDATE_SIMPLE);
  if (res == GSASL_CANNOT_VALIDATE)
    {
      const char *key;
      char *normkey;

      gsasl_property_set (sctx, GSASL_PASSWORD, NULL);

      key = gsasl_property_get (sctx, GSASL_PASSWORD);
      if (!key)
	{
	  free (password);
	  return GSASL_NO_PASSWORD;
	}

      normkey = gsasl_stringprep_saslprep (key, NULL);
      if (normkey == NULL)
	{
	  free (password);
	  return GSASL_SASLPREP_ERROR;
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
