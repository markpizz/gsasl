/* xstep.c --- Perform one SASL authentication step.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
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
 * You should have received a copy of the GNU Lesser General Public License
 * License along with GNU SASL Library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

/**
 * gsasl_step:
 * @sctx: libgsasl session handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: newly allocated output byte array.
 * @output_len: pointer to output variable with size of output byte array.
 *
 * Perform one step of SASL authentication.  This reads data from the
 * other end (from @input and @input_len), processes it (potentially
 * invoking callbacks to the application), and writes data to server
 * (into newly allocated variable @output and @output_len that
 * indicate the length of @output).
 *
 * The contents of the @output buffer is unspecified if this functions
 * returns anything other than GSASL_OK or GSASL_NEEDS_MORE.  If this
 * function return GSASL_OK or GSASL_NEEDS_MORE, however, the @output
 * buffer is allocated by this function, and it is the responsibility
 * of caller to deallocate it by calling free (@output).
 *
 * Return value: Returns GSASL_OK if authenticated terminated
 *   successfully, GSASL_NEEDS_MORE if more data is needed, or error
 *   code.
 **/
int
gsasl_step (Gsasl_session * sctx,
	    const char *input, size_t input_len,
	    char **output, size_t * output_len)
{
  Gsasl_step_function step;

  if (sctx == NULL)
    return GSASL_INVALID_HANDLE;

  if (sctx->clientp)
    step = sctx->mech->client.step;
  else
    step = sctx->mech->server.step;

  return step (sctx, sctx->mech_data, input, input_len, output, output_len);
}

/**
 * gsasl_step64:
 * @sctx: libgsasl client handle.
 * @b64input: input base64 encoded byte array.
 * @b64output: newly allocated output base64 encoded byte array.
 *
 * This is a simple wrapper around gsasl_step() that base64 decodes
 * the input and base64 encodes the output.
 *
 * The contents of the @b64output buffer is unspecified if this
 * functions returns anything other than GSASL_OK or GSASL_NEEDS_MORE.
 * If this function return GSASL_OK or GSASL_NEEDS_MORE, however, the
 * @b64output buffer is allocated by this function, and it is the
 * responsibility of caller to deallocate it by calling free
 * (@b64output).
 *
 * Return value: Returns GSASL_OK if authenticated terminated
 *   successfully, GSASL_NEEDS_MORE if more data is needed, or error
 *   code.
 **/
int
gsasl_step64 (Gsasl_session * sctx, const char *b64input, char **b64output)
{
  size_t input_len, output_len;
  char *input, *output;
  int res;

  if (b64input && strlen (b64input) > 0)
    {
      int len;

      input_len = strlen (b64input) + 1;
      input = (char *) malloc (input_len);
      if (input == NULL)
	return GSASL_MALLOC_ERROR;

      len = gsasl_base64_decode (b64input, input, input_len);
      if (len == -1)
	{
	  free (input);
	  return GSASL_BASE64_ERROR;
	}
      input_len = (size_t) len;
    }
  else
    {
      input = NULL;
      input_len = 0;
    }

  res = gsasl_step (sctx, input, input_len, &output, &output_len);

  if (res == GSASL_OK || res == GSASL_NEEDS_MORE)
    {
      size_t allen = output_len * 4 / 3 + 4;	/* XXX ? */
      int len;

      *b64output = malloc (allen);
      if (*b64output == NULL)
	{
	  if (input != NULL)
	    free (input);
	  if (output != NULL)
	    free (output);
	  return GSASL_MALLOC_ERROR;
	}

      len = gsasl_base64_encode (output, output_len, *b64output, allen);
      if (len == -1)
	{
	  if (input != NULL)
	    free (input);
	  if (output != NULL)
	    free (output);
	  return GSASL_BASE64_ERROR;
	}

      if (output != NULL)
	free (output);
    }

  if (input != NULL)
    free (input);

  return res;
}
