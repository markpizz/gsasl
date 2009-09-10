/* validate.c --- Validate consistency of SCRAM tokens.
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

/* Get prototypes. */
#include "validate.h"

/* Get strcmp, strlen. */
#include <string.h>

bool
scram_valid_client_first (struct scram_client_first *cf)
{
  /* Check that cbflag is one of permitted values. */
  switch (cf->cbflag)
    {
    case 'p':
    case 'n':
    case 'y':
      break;

    default:
      return false;
    }

  /* Check that cbname is only set when cbflag is p. */
  if (cf->cbflag == 'p' && cf->cbname == NULL)
    return false;
  else if (cf->cbflag != 'p' && cf->cbname != NULL)
    return false;

  /* FIXME check that cbname matches [A-Za-z0-9.-]. */

  /* We require a non-zero username string. */
  if (cf->username == NULL || *cf->username == '\0')
    return false;

  /* We require a non-zero client nonce. */
  if (cf->client_nonce == NULL || *cf->client_nonce == '\0')
    return false;

  /* Nonce cannot contain ','. */
  if (strchr (cf->client_nonce, ','))
    return false;

  /* FIXME check that client nonce is valid UTF-8. */

  return true;
}

bool
scram_valid_server_first (struct scram_server_first *sf)
{
  /* We require a non-zero nonce. */
  if (sf->nonce == NULL || *sf->nonce == '\0')
    return false;

  /* Nonce cannot contain ','. */
  if (strchr (sf->nonce, ','))
    return false;

  /* FIXME check that nonce is valid UTF-8. */

  /* We require a non-zero salt. */
  if (sf->salt == NULL || *sf->salt == '\0')
    return false;

  /* FIXME check that salt is valid base64. */
  if (strchr (sf->salt, ','))
    return false;

  if (sf->iter == 0)
    return false;

  return true;
}
