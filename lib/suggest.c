/* suggest.c	suggest client and server mechanism in a set of mechanisms
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

#ifdef USE_CLIENT
/**
 * gsasl_client_suggest_mechanism:
 * @ctx: libgsasl handle.
 * @mechlist: input character array with SASL mechanism names,
 * separated by invalid characters (e.g. SPC).
 *
 * Return value: Returns name of "best" SASL mechanism supported by
 * the libgsasl client which is present in the input string.
 **/
const char *
gsasl_client_suggest_mechanism (Gsasl_ctx * ctx, const char *mechlist)
{
  /* XXX parse mechlist */
  return ctx->client_mechs[0].name;
}
#endif

#if USE_SERVER
/**
 * gsasl_server_suggest_mechanism:
 * @ctx: libgsasl handle.
 * @mechlist: input character array with SASL mechanism names,
 * separated by invalid characters (e.g. SPC).
 *
 * Return value: Returns name of "best" SASL mechanism supported by
 * the libgsasl server which is present in the input string.
 **/
const char *
gsasl_server_suggest_mechanism (Gsasl_ctx * ctx, const char *mechlist)
{
  /* XXX parse mechlist */
  return ctx->server_mechs[0].name;
}
#endif
