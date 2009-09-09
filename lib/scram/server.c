/* server.c --- SASL CRAM-MD5 server side functions.
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

/* Get memcpy, strdup, strlen. */
#include <string.h>

#include "tokens.h"
#include "parser.h"

#define SNONCE_ENTROPY_BYTES 16

struct scram_server_state
{
  int step;
  char *cnonce;
  char snonce[SNONCE_ENTROPY_BYTES + 1];
  struct scram_client_first cf;
};

int
_gsasl_scram_sha1_server_start (Gsasl_session * sctx, void **mech_data)
{
  struct scram_server_state *state;
  size_t i;
  int rc;

  state = (struct scram_server_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;
  state->cnonce = NULL;

  rc = gsasl_nonce (state->snonce, SNONCE_ENTROPY_BYTES);
  if (rc != GSASL_OK)
    return rc;

  state->snonce[SNONCE_ENTROPY_BYTES] = '\0';

  for (i = 0; i < SNONCE_ENTROPY_BYTES; i++)
    {
      state->snonce[i] &= 0x7f;

      if (state->snonce[i] == '\0')
	state->snonce[i]++;

      if (state->snonce[i] == ',')
	state->snonce[i]++;
    }

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_scram_sha1_server_step (Gsasl_session * sctx,
			       void *mech_data,
			       const char *input,
			       size_t input_len,
			       char **output, size_t * output_len)
{
  struct scram_server_state *state = mech_data;
  int res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;

  *output = NULL;
  *output_len = 0;

  switch (state->step)
    {
    case 0:
      {
	if (scram_parse_client_first (input, input_len, &state->cf) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (scram_valid_client_first (state->cf) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

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
_gsasl_scram_sha1_server_finish (Gsasl_session * sctx, void *mech_data)
{
  struct scram_server_state *state = mech_data;

  if (!state)
    return;

  free (state->cnonce);
  free (state);
}
