/* obsolete.c	obsolete functions kept around for backwards compatibility.
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
 * gsasl_client_listmech:
 * @ctx: libgsasl handle.
 * @out: output character array.
 * @outlen: input maximum size of output character array, on output
 * contains actual length of output array.
 *
 * Write SASL names, separated by space, of mechanisms supported by
 * the libgsasl client to the output array.  To find out how large the
 * output array must be, call this function with out=NULL.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_client_listmech (Gsasl_ctx * ctx, char *out, size_t * outlen)
{
  char *tmp;
  int rc;

  rc = gsasl_client_mechlist (ctx, &tmp);

  if (rc == GSASL_OK)
    {
      size_t tmplen = strlen (tmp);

      if (tmplen >= *outlen)
	return GSASL_TOO_SMALL_BUFFER;

      if (out)
	strcpy (out, tmp);
      *outlen = tmplen;
    }

  return rc;
}
#endif

#ifdef USE_SERVER
/**
 * gsasl_server_listmech:
 * @ctx: libgsasl handle.
 * @out: output character array.
 * @outlen: input maximum size of output character array, on output
 * contains actual length of output array.
 *
 * Write SASL names, separated by space, of mechanisms supported by
 * the libgsasl server to the output array.  To find out how large the
 * output array must be, call this function with out=NULL.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_server_listmech (Gsasl_ctx * ctx, char *out, size_t * outlen)
{
  char *tmp;
  int rc;

  rc = gsasl_server_mechlist (ctx, &tmp);

  if (rc == GSASL_OK)
    {
      size_t tmplen = strlen (tmp);

      if (tmplen >= *outlen)
	return GSASL_TOO_SMALL_BUFFER;

      if (out)
	strcpy (out, tmp);
      *outlen = tmplen;
    }

  return rc;
}
#endif
