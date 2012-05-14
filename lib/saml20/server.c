/* server.c --- SAML20 mechanism, server side.
 * Copyright (C) 2010-2012 Simon Josefsson
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Get specification. */
#include "saml20.h"

/* Get strdup, strlen. */
#include <string.h>

/* Get free. */
#include <stdlib.h>

/* Get _gsasl_parse_gs2_header. */
#include "mechtools.h"

struct saml20_server_state
{
  int step;
};

int
_gsasl_saml20_server_start (Gsasl_session * sctx, void **mech_data)
{
  struct saml20_server_state *state;

  state = (struct saml20_server_state *) calloc (sizeof (*state), 1);
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_saml20_server_step (Gsasl_session * sctx,
			   void *mech_data,
			   const char *input, size_t input_len,
			   char **output, size_t * output_len)
{
  struct saml20_server_state *state = mech_data;
  int res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;

  *output_len = 0;
  *output = NULL;

  switch (state->step)
    {
    case 0:
      {
	const char *p;
	char *authzid;
	size_t headerlen;

	if (input_len == 0)
	  return GSASL_NEEDS_MORE;

	res = _gsasl_parse_gs2_header (input, input_len,
				       &authzid, &headerlen);
	if (res != GSASL_OK)
	  return res;

	if (authzid)
	  {
	    gsasl_property_set (sctx, GSASL_AUTHZID, authzid);
	    free (authzid);
	  }

	input += headerlen;
	input_len -= headerlen;

	gsasl_property_set_raw (sctx, GSASL_SAML20_IDP_IDENTIFIER,
				input, input_len);

	p = gsasl_property_get (sctx, GSASL_SAML20_REDIRECT_URL);
	if (!p || !*p)
	  return GSASL_NO_SAML20_REDIRECT_URL;

	*output_len = strlen (p);
	*output = malloc (*output_len);
	if (!*output)
	  return GSASL_MALLOC_ERROR;

	memcpy (*output, p, *output_len);

	res = GSASL_NEEDS_MORE;
	state->step++;
	break;
      }

    case 1:
      {
	if (!(input_len == 1 && *input == '='))
	  return GSASL_MECHANISM_PARSE_ERROR;

	res = gsasl_callback (NULL, sctx, GSASL_VALIDATE_SAML20);
	if (res != GSASL_OK)
	  return res;

	*output = NULL;
	*output_len = 0;

	res = GSASL_OK;
	state->step++;
	break;
      }

    default:
      break;
    }

  return res;
}

void
_gsasl_saml20_server_finish (Gsasl_session * sctx, void *mech_data)
{
  struct saml20_server_state *state = mech_data;

  if (!state)
    return;

  free (state);
}
