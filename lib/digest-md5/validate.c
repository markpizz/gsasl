/* validate.c --- Validate consistency of DIGEST-MD5 tokens.
 * Copyright (C) 2004  Simon Josefsson
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
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get prototypes. */
#include "validate.h"

int
digest_md5_validate (digest_md5_challenge *c, digest_md5_response *r)
{
  if (!c->nonce || r->nonce)
    return -1;

  if (strcmp (c->nonce, r->nonce) != 0)
    return -1;

  if (r->nc != 1)
    return -1;

  if (c->utf8 != r->utf8)
    return -1;

  if (!((c->qops ? c->qops : DIGEST_MD5_QOP_AUTH) &
	(r->qop ? r->qop : DIGEST_MD5_QOP_AUTH)))
    return -1;

  if ((r->qop & DIGEST_MD5_QOP_AUTH) && !(c->ciphers & r->cipher))
    return -1;

  /* FIXME: Check more? */

  return 0;
}
