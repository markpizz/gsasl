/* supportp.c	tell if a specific mechanism is support by the client or server
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

static int
_gsasl_support_p (_Gsasl_mechanism * mechs, size_t n_mechs, const char *name)
{
  int i;

  for (i = 0; i < n_mechs; i++)
    if (name && strcmp (name, mechs[i].name) == 0)
      return 1;

  return 0;
}

/**
 * gsasl_client_support_p:
 * @ctx: libgsasl handle.
 * @name: name of SASL mechanism.
 *
 * Return value: Returns 1 if the libgsasl client supports the named
 * mechanism, otherwise 0.
 **/
int
gsasl_client_support_p (Gsasl_ctx * ctx, const char *name)
{
  return _gsasl_support_p (ctx->client_mechs, ctx->n_client_mechs, name);
}

/**
 * gsasl_server_support_p:
 * @ctx: libgsasl handle.
 * @name: name of SASL mechanism.
 *
 * Return value: Returns 1 if the libgsasl server supports the named
 * mechanism, otherwise 0.
 **/
int
gsasl_server_support_p (Gsasl_ctx * ctx, const char *name)
{
  return _gsasl_support_p (ctx->server_mechs, ctx->n_server_mechs, name);
}
