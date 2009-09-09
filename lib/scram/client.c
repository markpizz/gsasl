/* client.c --- SASL SCRAM client side functions.
 * Copyright (C) 2009  Simon Josefsson
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
#include "scram.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

#include "tokens.h"
#include "printer.h"

#define CNONCE_ENTROPY_BYTES 16

struct scram_client_state
{
  int step;
  char cnonce[CNONCE_ENTROPY_BYTES + 1];
};

int
_gsasl_scram_sha1_client_start (Gsasl_session * sctx, void **mech_data)
{
  struct scram_client_state *state;
  size_t i;
  int rc;

  state = (struct scram_client_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;

  rc = gsasl_nonce (state->cnonce, CNONCE_ENTROPY_BYTES);
  if (rc != GSASL_OK)
    return rc;

  state->cnonce[CNONCE_ENTROPY_BYTES] = '\0';

  for (i = 0; i < CNONCE_ENTROPY_BYTES; i++)
    {
      state->cnonce[i] &= 0x7f;

      if (state->cnonce[i] == '\0')
	state->cnonce[i]++;

      if (state->cnonce[i] == ',')
	state->cnonce[i]++;
    }

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_scram_sha1_client_step (Gsasl_session * sctx,
			       void *mech_data,
			       const char *input, size_t input_len,
			       char **output, size_t * output_len)
{
  struct scram_client_state *state = mech_data;
  int res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;

  switch (state->step)
    {
    case 0:
      {
	struct scram_client_first cf;
	const char *p;
	int rc;

	memset (&cf, 0, sizeof (cf));

	cf.client_nonce = state->cnonce;
	cf.cbflag = 'n';

	p = gsasl_property_get (sctx, GSASL_AUTHID);
	if (!p)
	  return GSASL_NO_AUTHID;

	/* XXX Use query strings here?  Specification is unclear. */
	rc = gsasl_saslprep (p, 0, &cf.username, NULL);
	if (rc != GSASL_OK)
	  return rc;

	rc = scram_print_client_first (&cf, output);
	if (rc != 0)
	  return GSASL_MALLOC_ERROR;

	*output_len = strlen (*output);

	gsasl_free (cf.username);

	state->step++;
	return GSASL_NEEDS_MORE;
	break;
      }

    default:
      break;
    }

  return res;
}

void
_gsasl_scram_sha1_client_finish (Gsasl_session * sctx, void *mech_data)
{
  struct scram_client_state *state = mech_data;

  if (!state)
    return;

  free (state);
}
