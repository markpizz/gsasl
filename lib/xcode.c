/* xcode.c	encode and decode application payload in libgsasl session
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of libgsasl.
 *
 * Libgsasl is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Libgsasl is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with libgsasl; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

/**
 * gsasl_encode:
 * @xctx: libgsasl session handle.
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
gsasl_encode (Gsasl_session_ctx * xctx,
	      const char *input,
	      size_t input_len, char *output, size_t * output_len)
{
  int res;
  _Gsasl_code_function code = xctx ? (xctx->clientp ?
				      xctx->mech->client.encode :
				      xctx->mech->server.encode) : NULL;

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
	code (xctx, xctx->mech_data, input, input_len, output, output_len);
    }

  return res;
}

/**
 * gsasl_decode:
 * @xctx: libgsasl session handle.
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
gsasl_decode (Gsasl_session_ctx * xctx,
	      const char *input,
	      size_t input_len, char *output, size_t * output_len)
{
  int res;
  _Gsasl_code_function code = xctx ? (xctx->clientp ?
				      xctx->mech->client.decode :
				      xctx->mech->server.decode) : NULL;

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
	code (xctx, xctx->mech_data, input, input_len, output, output_len);
    }

  return res;
}
