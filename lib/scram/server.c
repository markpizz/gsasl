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

/* Get malloc, free, strtoul. */
#include <stdlib.h>

/* Get ULONG_MAX. */
#include <limits.h>

/* Get memcpy, strdup, strlen. */
#include <string.h>

#include "tokens.h"
#include "parser.h"
#include "printer.h"

#define DEFAULT_SALT_BYTES 8
#define SNONCE_ENTROPY_BYTES 16

struct scram_server_state
{
  int step;
  char snonce[SNONCE_ENTROPY_BYTES + 1];
  char salt[DEFAULT_SALT_BYTES + 1];
  struct scram_client_first cf;
  struct scram_server_first sf;
  struct scram_client_final cl;
  struct scram_server_final sl;
};

int
_gsasl_scram_sha1_server_start (Gsasl_session * sctx, void **mech_data)
{
  struct scram_server_state *state;
  size_t i;
  int rc;

  state = (struct scram_server_state *) calloc (sizeof (*state), 1);
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

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

  rc = gsasl_nonce (state->salt, DEFAULT_SALT_BYTES);
  if (rc != GSASL_OK)
    return rc;

  state->salt[DEFAULT_SALT_BYTES] = '\0';

  for (i = 0; i < DEFAULT_SALT_BYTES; i++)
    {
      state->salt[i] &= 0x7f;

      if (state->salt[i] == '\0')
	state->salt[i]++;

      if (state->salt[i] == ',')
	state->salt[i]++;
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
  int rc;

  *output = NULL;
  *output_len = 0;

  switch (state->step)
    {
    case 0:
      {
	if (strlen (input) != input_len)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (scram_parse_client_first (input, &state->cf) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	/* Create new nonce. */
	{
	  size_t cnlen = strlen (state->cf.client_nonce);

	  state->sf.nonce = malloc (cnlen + SNONCE_ENTROPY_BYTES + 1);
	  if (!state->sf.nonce)
	    return GSASL_MALLOC_ERROR;

	  memcpy (state->sf.nonce, state->cf.client_nonce, cnlen);
	  memcpy (state->sf.nonce + cnlen, state->snonce,
		  SNONCE_ENTROPY_BYTES);
	  state->sf.nonce[cnlen + SNONCE_ENTROPY_BYTES] = '\0';
	}

	{
	  const char *p = gsasl_property_get (sctx, GSASL_SCRAM_ITER);
	  if (p)
	    state->sf.iter = strtoul (p, NULL, 10);
	  if (!p || state->sf.iter == 0 || state->sf.iter == ULONG_MAX)
	    state->sf.iter = 4096;
	}

	{
	  const char *p = gsasl_property_get (sctx, GSASL_SCRAM_SALT);
	  if (p)
	    state->sf.salt = strdup (p);
	  else
	    state->sf.salt = strdup (state->salt);
	}

	rc = scram_print_server_first (&state->sf, output);
	if (rc != 0)
	  return GSASL_MALLOC_ERROR;
	*output_len = strlen (*output);

	state->step++;
	return GSASL_NEEDS_MORE;
	break;
      }

    case 1:
      {
	if (strlen (input) != input_len)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (scram_parse_client_final (input, &state->cl) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	state->sl.verifier = strdup ("verifier");

	rc = scram_print_server_final (&state->sl, output);
	if (rc != 0)
	  return GSASL_MALLOC_ERROR;
	*output_len = strlen (*output);

	state->step++;
	return GSASL_OK;
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
  
  scram_free_client_first (&state->cf);
  scram_free_server_first (&state->sf);
  scram_free_client_final (&state->cl);
  scram_free_server_final (&state->sl);

  free (state);
}
