/* xcode.c	encode and decode application payload in libgsasl session
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

/**
 * gsasl_encode:
 * @sctx: libgsasl session handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: output byte array.
 * @output_len: size of output byte array.
 *
 * Encode data according to negotiated SASL mechanism.  This might mean
 * that data is integrity or privacy protected.
 *
 * Return value: Returns GSASL_OK if encoding was successful, otherwise
 * an error code.
 **/
int
gsasl_encode (Gsasl_session_ctx * sctx,
	      const char *input,
	      size_t input_len, char *output, size_t * output_len)
{
  int res;
  _Gsasl_code_function code = NULL;

  if (sctx)
    {
      if (sctx->clientp)
	code = sctx->mech->client.encode;
      else
	code = sctx->mech->server.encode;
    }

  if (code == NULL)
    {
      *output_len = input_len;
      if (output)
	memcpy (output, input, input_len);
      res = GSASL_OK;
    }
  else
    {
      res =
	code (sctx, sctx->mech_data, input, input_len, output, output_len);
    }

  return res;
}

/**
 * gsasl_decode:
 * @sctx: libgsasl session handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: output byte array.
 * @output_len: size of output byte array.
 *
 * Decode data according to negotiated SASL mechanism.  This might mean
 * that data is integrity or privacy protected.
 *
 * Return value: Returns GSASL_OK if encoding was successful, otherwise
 * an error code.
 **/
int
gsasl_decode (Gsasl_session_ctx * sctx,
	      const char *input,
	      size_t input_len, char *output, size_t * output_len)
{
  int res;
  _Gsasl_code_function code = NULL;

  if (sctx)
    {
      if (sctx->clientp)
	code = sctx->mech->client.decode;
      else
	code = sctx->mech->server.decode;
    }

  if (code == NULL)
    {
      *output_len = input_len;
      if (output)
	memcpy (output, input, input_len);
      res = GSASL_OK;
    }
  else
    {
      res =
	code (sctx, sctx->mech_data, input, input_len, output, output_len);
    }

  return res;
}
