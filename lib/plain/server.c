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
  const char *authzidptr = input;
  char *authidptr = NULL;
  char *passwordptr = NULL;
  char *passwdz = NULL, *passprep = NULL, *authidprep = NULL;
  int res;

  *output_len = 0;
  *output = NULL;

  if (input_len == 0)
    return GSASL_NEEDS_MORE;

  /* Parse input. */
  {
    authidptr = memchr (input, 0, input_len - 1);
    if (authidptr)
      {
	authidptr++;
	passwordptr = memchr (authidptr, 0, input_len - strlen (input) - 1);
	if (passwordptr)
	  passwordptr++;
	else
	  return GSASL_MECHANISM_PARSE_ERROR;
      }
    else
      return GSASL_MECHANISM_PARSE_ERROR;

    /* As the NUL (U+0000) character is used as a deliminator, the NUL
       (U+0000) character MUST NOT appear in authzid, authcid, or passwd
       productions. */
    if (memchr (passwordptr, 0, input_len - (passwordptr - input)))
      return GSASL_MECHANISM_PARSE_ERROR;
  }

  /* Remember authzid, authid, and password.  Authid and password need
     to be prepared.  */
  {
    gsasl_property_set (sctx, GSASL_AUTHZID, authzidptr);

    /* FIXME: Specificaiton is unclear on whether unassigned code
       points are allowed or not.  We don't allow them. */
    res = gsasl_saslprep (authidptr, 0, &authidprep, NULL);
    if (res != GSASL_OK)
      return res;

    gsasl_property_set (sctx, GSASL_AUTHID, authidprep);

    free (authidprep);

    /* Need to zero terminate password... */
    passwdz = malloc (input_len - (passwordptr - input) + 1);
    if (passwdz == NULL)
      return GSASL_MALLOC_ERROR;
    memcpy (passwdz, passwordptr, input_len - (passwordptr - input));
    passwdz[input_len - (passwordptr - input)] = '\0';

    /* FIXME: Specificaiton is unclear on whether unassigned code
       points are allowed or not.  We don't allow them. */
    res = gsasl_saslprep (passwdz, 0, &passprep, NULL);
    free (passwdz);
    if (res != GSASL_OK)
      return res;

    gsasl_property_set (sctx, GSASL_PASSWORD, passprep);
  }

  /* Authorization.  Let application verify credentials internally,
     but fall back to deal with it locally...*/
  res = gsasl_callback (NULL, sctx, GSASL_VALIDATE_SIMPLE);
  if (res == GSASL_NO_CALLBACK)
    {
      const char *key;
      char *normkey;

      gsasl_callback (sctx, GSASL_PASSWORD);
      key = gsasl_property_fast (sctx, GSASL_PASSWORD);
      if (!key)
	return GSASL_NO_PASSWORD;

      /* FIXME: Specification is unclear on whether unassigned code
	 points are allowed or not.  We don't allow them. */
      res = gsasl_saslprep (key, 0, &normkey, NULL);
      if (res != GSASL_OK)
	return res;

      if (strlen (passprep) == strlen (normkey) &&
	  memcmp (normkey, passprep, strlen (normkey)) == 0)
	res = GSASL_OK;
      else
	res = GSASL_AUTHENTICATION_ERROR;
      free (normkey);
    }

  return res;
}
