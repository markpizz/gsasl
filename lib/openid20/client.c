/* client.c --- OPENID20 mechanism, client side.
 * Copyright (C) 2011  Simon Josefsson
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
# include "config.h"
#endif

/* Get specification. */
#include "openid20.h"

/* Get strdup, strlen. */
#include <string.h>

/* Get calloc, free. */
#include <stdlib.h>

/* Get bool. */
#include <stdbool.h>

/* Get _gsasl_gs2_generate_header. */
#include "mechtools.h"

struct openid20_client_state
{
  int step;
};

int
_gsasl_openid20_client_start (Gsasl_session * sctx, void **mech_data)
{
  struct openid20_client_state *state;

  state = (struct openid20_client_state *) calloc (sizeof (*state), 1);
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_openid20_client_step (Gsasl_session * sctx,
			   void *mech_data,
			   const char *input, size_t input_len,
			   char **output, size_t * output_len)
{
  struct openid20_client_state *state = mech_data;
  int res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;

  switch (state->step)
    {
    case 0:
      {
	const char *authzid = gsasl_property_get (sctx, GSASL_AUTHZID);
	const char *p;

	p = gsasl_property_get (sctx, GSASL_OPENID20_AUTH_IDENTIFIER);
	if (!p || !*p)
	  return GSASL_NO_OPENID20_AUTH_IDENTIFIER;

	res = _gsasl_gs2_generate_header (false, 'n', NULL, authzid,
					  strlen (p), p,
					  output, output_len);
	if (res == GSASL_OK)
	  return res;

	res = GSASL_NEEDS_MORE;
	state->step++;
	break;
      }

    default:
      break;
    }

  return res;
}

void
_gsasl_openid20_client_finish (Gsasl_session * sctx, void *mech_data)
{
  struct openid20_client_state *state = mech_data;

  if (!state)
    return;

  free (state);
}
