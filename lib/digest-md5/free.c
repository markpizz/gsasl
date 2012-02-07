/* free.h --- Free allocated data in DIGEST-MD5 token structures.
 * Copyright (C) 2004-2012 Simon Josefsson
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
#include "free.h"

/* Get free. */
#include <stdlib.h>

/* Get memset. */
#include <string.h>

void
digest_md5_free_challenge (digest_md5_challenge * c)
{
  size_t i;

  for (i = 0; i < c->nrealms; i++)
    free (c->realms[i]);
  free (c->realms);
  free (c->nonce);

  memset (c, 0, sizeof (*c));
}

void
digest_md5_free_response (digest_md5_response * r)
{
  free (r->username);
  free (r->realm);
  free (r->nonce);
  free (r->cnonce);
  free (r->digesturi);
  free (r->authzid);

  memset (r, 0, sizeof (*r));
}

void
digest_md5_free_finish (digest_md5_finish * f)
{
  memset (f, 0, sizeof (*f));
}
