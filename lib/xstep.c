/* xstep.c	perform one SASL authentication step
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
 * gsasl_client_step:
 * @sctx: libgsasl client handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: output byte array.
 * @output_len: size of output byte array.
 *
 * Perform one step of SASL authentication in client.  This reads data
 * from server (specified with input and input_len), processes it
 * (potentially invoking callbacks to the application), and writes
 * data to server (into variables output and output_len).
 *
 * The contents of the output buffer is unspecified if this functions
 * returns anything other than GSASL_NEEDS_MORE.
 *
 * Return value: Returns GSASL_OK if authenticated terminated
 * successfully, GSASL_NEEDS_MORE if more data is needed, or error
 * code.
 **/
int
gsasl_client_step (Gsasl_session_ctx * sctx,
		   const char *input,
		   size_t input_len, char *output, size_t * output_len)
{
#ifdef USE_CLIENT
  return sctx->mech->client.step (sctx, sctx->mech_data,
				  input, input_len, output, output_len);

#else
  return GSASL_UNKNOWN_MECHANISM;
#endif
}

/**
 * gsasl_server_step:
 * @sctx: libgsasl server handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: output byte array.
 * @output_len: size of output byte array.
 *
 * Perform one step of SASL authentication in server.  This reads data
 * from client (specified with input and input_len), processes it
 * (potentially invoking callbacks to the application), and writes
 * data to client (into variables output and output_len).
 *
 * The contents of the output buffer is unspecified if this functions
 * returns anything other than GSASL_NEEDS_MORE.
 *
 * Return value: Returns GSASL_OK if authenticated terminated
 * successfully, GSASL_NEEDS_MORE if more data is needed, or error
 * code.
 **/
int
gsasl_server_step (Gsasl_session_ctx * sctx,
		   const char *input,
		   size_t input_len, char *output, size_t * output_len)
{
#ifdef USE_SERVER
  return sctx->mech->server.step (sctx, sctx->mech_data,
				  input, input_len, output, output_len);
#else
  return GSASL_UNKNOWN_MECHANISM;
#endif
}

/**
 * gsasl_client_step_base64:
 * @sctx: libgsasl client handle.
 * @b64input: input base64 encoded byte array.
 * @b64output: output base64 encoded byte array.
 * @b64output_len: size of output base64 encoded byte array.
 *
 * This is a simple wrapper around gsasl_client_step() that base64
 * decodes the input and base64 encodes the output.
 *
 * Return value: See gsasl_client_step().
 **/
int
gsasl_client_step_base64 (Gsasl_session_ctx * sctx,
			  const char *b64input,
			  char *b64output, size_t b64output_len)
{
#ifdef USE_CLIENT
  size_t input_len, output_len;
  char *input, *output;
  int res;

  if (b64input && strlen (b64input) > 0)
    {
      input_len = strlen (b64input) + 1;
      input = (char *) malloc (input_len);

      input_len = gsasl_base64_decode (b64input, input, input_len);
      if ((int)input_len == -1)
	{
	  free (input);
	  return GSASL_BASE64_ERROR;
	}
    }
  else
    {
      input = NULL;
      input_len = 0;
    }

  if (b64output && b64output_len > 0)
    {
      *b64output = '\0';
      output_len = b64output_len;	/* As good guess as any */
      output = (char *) malloc (output_len);
    }
  else
    {
      output = NULL;
      output_len = 0;
    }

  res = gsasl_client_step (sctx, input, input_len, output, &output_len);

  if ((res == GSASL_OK || res == GSASL_NEEDS_MORE) && output
      && output_len > 0)
    {
      output_len = gsasl_base64_encode (output, output_len,
					b64output, b64output_len);
      if ((int)output_len == -1)
	{
	  free (output);
	  free (input);
	  return GSASL_BASE64_ERROR;
	}
    }

  if (output != NULL)
    free (output);
  if (input != NULL)
    free (input);

  return res;
#else
  return GSASL_UNKNOWN_MECHANISM;
#endif
}

/**
 * gsasl_server_step_base64:
 * @sctx: libgsasl server handle.
 * @b64input: input base64 encoded byte array.
 * @b64output: output base64 encoded byte array.
 * @b64output_len: size of output base64 encoded byte array.
 *
 * This is a simple wrapper around gsasl_server_step() that base64
 * decodes the input and base64 encodes the output.
 *
 * Return value: See gsasl_server_step().
 **/
int
gsasl_server_step_base64 (Gsasl_session_ctx * sctx,
			  const char *b64input,
			  char *b64output, size_t b64output_len)
{
#ifdef USE_SERVER
  size_t input_len, output_len;
  char *input, *output;
  int res;

  if (b64input && strlen (b64input) > 0)
    {
      input_len = strlen (b64input) + 1;
      input = (char *) malloc (input_len);

      input_len = gsasl_base64_decode (b64input, input, input_len);
      if ((int)input_len == -1)
	{
	  free (input);
	  return GSASL_BASE64_ERROR;
	}
    }
  else
    {
      input = NULL;
      input_len = 0;
    }

  if (b64output && b64output_len > 0)
    {
      *b64output = '\0';
      output_len = b64output_len;	/* As good guess as any */
      output = (char *) malloc (output_len);
    }
  else
    {
      output = NULL;
      output_len = 0;
    }

  res = gsasl_server_step (sctx, input, input_len, output, &output_len);

  if ((res == GSASL_OK || res == GSASL_NEEDS_MORE) && output
      && output_len > 0)
    {
      output_len = gsasl_base64_encode (output, output_len,
					b64output, b64output_len);
      if ((int)output_len == -1)
	{
	  free (output);
	  free (input);
	  return GSASL_BASE64_ERROR;
	}
    }

  if (output != NULL)
    free (output);
  if (input != NULL)
    free (input);

  return res;
#else
  return GSASL_UNKNOWN_MECHANISM;
#endif
}
