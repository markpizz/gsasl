/* server.c --- OPENID20 mechanism, server side.
 * Copyright (C) 2011-2012 Simon Josefsson
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

/* Get _gsasl_parse_gs2_header. */
#include "mechtools.h"

struct openid20_server_state
{
  int step;
};

int
_gsasl_openid20_server_start (Gsasl_session * sctx, void **mech_data)
{
  struct openid20_server_state *state;

  state = (struct openid20_server_state *) calloc (sizeof (*state), 1);
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_openid20_server_step (Gsasl_session * sctx,
			   void *mech_data,
			   const char *input, size_t input_len,
			   char **output, size_t * output_len)
{
  struct openid20_server_state *state = mech_data;
  int res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;

  *output_len = 0;
  *output = NULL;

  switch (state->step)
    {
    default:
      break;
    }

  return res;
}

void
_gsasl_openid20_server_finish (Gsasl_session * sctx, void *mech_data)
{
  struct openid20_server_state *state = mech_data;

  if (!state)
    return;

  free (state);
}
