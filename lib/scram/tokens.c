/* tokens.c --- Free allocated data in SCRAM tokens.
 * Copyright (C) 2009-2012 Simon Josefsson
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

/* Get prototypes. */
#include "tokens.h"

/* Get free. */
#include <stdlib.h>

/* Get memset. */
#include <string.h>

void
scram_free_client_first (struct scram_client_first *cf)
{
  free (cf->cbname);
  free (cf->authzid);
  free (cf->username);
  free (cf->client_nonce);

  memset (cf, 0, sizeof (*cf));
}

void
scram_free_server_first (struct scram_server_first *sf)
{
  free (sf->nonce);
  free (sf->salt);

  memset (sf, 0, sizeof (*sf));
}

void
scram_free_client_final (struct scram_client_final *cl)
{
  free (cl->cbind);
  free (cl->nonce);
  free (cl->proof);

  memset (cl, 0, sizeof (*cl));
}

void
scram_free_server_final (struct scram_server_final *sl)
{
  free (sl->verifier);

  memset (sl, 0, sizeof (*sl));
}
