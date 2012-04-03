/* validate.c --- Validate consistency of SCRAM tokens.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
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

  if (cf->cbname)
    {
      const char *p = cf->cbname;

      while (*p && strchr ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			   "abcdefghijklmnopqrstuvwxyz" "0123456789.-", *p))
	p++;
      if (*p)
	return false;
    }

  /* We require a non-zero username string. */
  if (cf->username == NULL || *cf->username == '\0')
    return false;

  /* We require a non-zero client nonce. */
  if (cf->client_nonce == NULL || *cf->client_nonce == '\0')
    return false;

  /* Nonce cannot contain ','. */
  if (strchr (cf->client_nonce, ','))
    return false;

  return true;
}

bool
scram_valid_server_first (struct scram_server_first * sf)
{
  /* We require a non-zero nonce. */
  if (sf->nonce == NULL || *sf->nonce == '\0')
    return false;

  /* Nonce cannot contain ','. */
  if (strchr (sf->nonce, ','))
    return false;

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

bool
scram_valid_client_final (struct scram_client_final * cl)
{
  /* We require a non-zero cbind. */
  if (cl->cbind == NULL || *cl->cbind == '\0')
    return false;

  /* FIXME check that cbind is valid base64. */
  if (strchr (cl->cbind, ','))
    return false;

  /* We require a non-zero nonce. */
  if (cl->nonce == NULL || *cl->nonce == '\0')
    return false;

  /* Nonce cannot contain ','. */
  if (strchr (cl->nonce, ','))
    return false;

  /* We require a non-zero proof. */
  if (cl->proof == NULL || *cl->proof == '\0')
    return false;

  /* FIXME check that proof is valid base64. */
  if (strchr (cl->proof, ','))
    return false;

  return true;
}

bool
scram_valid_server_final (struct scram_server_final * sl)
{
  /* We require a non-zero verifier. */
  if (sl->verifier == NULL || *sl->verifier == '\0')
    return false;

  /* FIXME check that verifier is valid base64. */
  if (strchr (sl->verifier, ','))
    return false;

  return true;
}
