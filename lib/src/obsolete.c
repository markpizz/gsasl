/* obsolete.c --- Obsolete functions kept around for backwards compatibility.
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
 *
 * Deprecated: Use gsasl_client_mechlist() instead.
 **/
int
gsasl_client_listmech (Gsasl * ctx, char *out, size_t * outlen)
{
  char *tmp;
  int rc;

  rc = gsasl_client_mechlist (ctx, &tmp);

  if (rc == GSASL_OK)
    {
      size_t tmplen = strlen (tmp);

      if (tmplen >= *outlen)
	{
	  free (tmp);
	  return GSASL_TOO_SMALL_BUFFER;
	}

      if (out)
	strcpy (out, tmp);
      *outlen = tmplen + 1;
      free (tmp);
    }

  return rc;
}

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
 *
 * Deprecated: Use gsasl_server_mechlist() instead.
 **/
int
gsasl_server_listmech (Gsasl * ctx, char *out, size_t * outlen)
{
  char *tmp;
  int rc;

  rc = gsasl_server_mechlist (ctx, &tmp);

  if (rc == GSASL_OK)
    {
      size_t tmplen = strlen (tmp);

      if (tmplen >= *outlen)
	{
	  free (tmp);
	  return GSASL_TOO_SMALL_BUFFER;
	}

      if (out)
	strcpy (out, tmp);
      *outlen = tmplen + 1;
      free (tmp);
    }

  return rc;
}

static int
_gsasl_step (Gsasl_session * sctx,
	     const char *input, size_t input_len,
	     char *output, size_t * output_len)
{
  char *tmp;
  size_t tmplen;
  int rc;

  rc = gsasl_step (sctx, input, input_len, &tmp, &tmplen);

  if (rc == GSASL_OK || rc == GSASL_NEEDS_MORE)
    {
      if (tmplen >= *output_len)
	{
	  free (tmp);
	  /* XXX We lose the step token here, don't we? */
	  return GSASL_TOO_SMALL_BUFFER;
	}

      if (output)
	memcpy (output, tmp, tmplen);
      *output_len = tmplen;
      free (tmp);
    }

  return rc;
}

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
 *
 * Deprecated: Use gsasl_step() instead.
 **/
int
gsasl_client_step (Gsasl_session * sctx,
		   const char *input,
		   size_t input_len, char *output, size_t * output_len)
{
  return _gsasl_step (sctx, input, input_len, output, output_len);
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
 *
 * Deprecated: Use gsasl_step() instead.
 **/
int
gsasl_server_step (Gsasl_session * sctx,
		   const char *input,
		   size_t input_len, char *output, size_t * output_len)
{
  return _gsasl_step (sctx, input, input_len, output, output_len);
}

static int
_gsasl_step64 (Gsasl_session * sctx,
	       const char *b64input, char *b64output, size_t b64output_len)
{
  char *tmp;
  int rc;

  rc = gsasl_step64 (sctx, b64input, &tmp);

  if (rc == GSASL_OK || rc == GSASL_NEEDS_MORE)
    {
      if (b64output_len <= strlen (tmp))
	{
	  free (tmp);
	  /* XXX We lose the step token here, don't we? */
	  return GSASL_TOO_SMALL_BUFFER;
	}

      if (b64output)
	strcpy (b64output, tmp);
      free (tmp);
    }

  return rc;
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
 *
 * Deprecated: Use gsasl_step64() instead.
 **/
int
gsasl_client_step_base64 (Gsasl_session * sctx,
			  const char *b64input,
			  char *b64output, size_t b64output_len)
{
  return _gsasl_step64 (sctx, b64input, b64output, b64output_len);
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
 *
 * Deprecated: Use gsasl_step64() instead.
 **/
int
gsasl_server_step_base64 (Gsasl_session * sctx,
			  const char *b64input,
			  char *b64output, size_t b64output_len)
{
  return _gsasl_step64 (sctx, b64input, b64output, b64output_len);
}

/**
 * gsasl_client_finish:
 * @sctx: libgsasl client handle.
 *
 * Destroy a libgsasl client handle.  The handle must not be used with
 * other libgsasl functions after this call.
 *
 * Deprecated: Use gsasl_finish() instead.
 **/
void
gsasl_client_finish (Gsasl_session * sctx)
{
  gsasl_finish (sctx);
}

/**
 * gsasl_server_finish:
 * @sctx: libgsasl server handle.
 *
 * Destroy a libgsasl server handle.  The handle must not be used with
 * other libgsasl functions after this call.
 *
 * Deprecated: Use gsasl_finish() instead.
 **/
void
gsasl_server_finish (Gsasl_session * sctx)
{
  gsasl_finish (sctx);
}

/**
 * gsasl_client_ctx_get:
 * @sctx: libgsasl client handle
 *
 * Return value: Returns the libgsasl handle given a libgsasl client handle.
 *
 * Deprecated: This function is not useful with the new 0.2.0 API.
 **/
Gsasl *
gsasl_client_ctx_get (Gsasl_session * sctx)
{
  return sctx->ctx;
}

/**
 * gsasl_client_application_data_set:
 * @sctx: libgsasl client handle.
 * @application_data: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl client handle.  The
 * application data can be later (for instance, inside a callback) be
 * retrieved by calling gsasl_client_application_data_get().  It is
 * normally used by the application to maintain state between the main
 * program and the callback.
 *
 * Deprecated: Use gsasl_callback_hook_set() instead.
 **/
void
gsasl_client_application_data_set (Gsasl_session * sctx,
				   void *application_data)
{
  gsasl_appinfo_set (sctx, application_data);
}

/**
 * gsasl_client_application_data_get:
 * @sctx: libgsasl client handle.
 *
 * Retrieve application specific data from libgsasl client handle. The
 * application data is set using gsasl_client_application_data_set().
 * It is normally used by the application to maintain state between
 * the main program and the callback.
 *
 * Return value: Returns the application specific data, or NULL.
 *
 * Deprecated: Use gsasl_callback_hook_get() instead.
 **/
void *
gsasl_client_application_data_get (Gsasl_session * sctx)
{
  return gsasl_appinfo_get (sctx);
}

/**
 * gsasl_server_ctx_get:
 * @sctx: libgsasl server handle
 *
 * Return value: Returns the libgsasl handle given a libgsasl server handle.
 *
 * Deprecated: This function is not useful with the new 0.2.0 API.
 **/
Gsasl *
gsasl_server_ctx_get (Gsasl_session * sctx)
{
  return sctx->ctx;
}

/**
 * gsasl_server_application_data_set:
 * @sctx: libgsasl server handle.
 * @application_data: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl server handle.  The
 * application data can be later (for instance, inside a callback) be
 * retrieved by calling gsasl_server_application_data_get().  It is
 * normally used by the application to maintain state between the main
 * program and the callback.
 *
 * Deprecated: Use gsasl_callback_hook_set() instead.
 **/
void
gsasl_server_application_data_set (Gsasl_session * sctx,
				   void *application_data)
{
  gsasl_appinfo_set (sctx, application_data);
}

/**
 * gsasl_server_application_data_get:
 * @sctx: libgsasl server handle.
 *
 * Retrieve application specific data from libgsasl server handle. The
 * application data is set using gsasl_server_application_data_set().
 * It is normally used by the application to maintain state between
 * the main program and the callback.
 *
 * Return value: Returns the application specific data, or NULL.
 *
 * Deprecated: Use gsasl_callback_hook_get() instead.
 **/
void *
gsasl_server_application_data_get (Gsasl_session * sctx)
{
  return gsasl_appinfo_get (sctx);
}

/**
 * gsasl_randomize:
 * @strong: 0 iff operation should not block, non-0 for very strong randomness.
 * @data: output array to be filled with random data.
 * @datalen: size of output array.
 *
 * Store cryptographically random data of given size in the provided
 * buffer.
 *
 * Return value: Returns %GSASL_OK iff successful.
 *
 * Deprecated: Use gsasl_random() or gsasl_nonce() instead.
 **/
int
gsasl_randomize (int strong, char *data, size_t datalen)
{
  if (strong)
    return gsasl_random (data, datalen);
  return gsasl_nonce (data, datalen);
}

/**
 * gsasl_ctx_get:
 * @sctx: libgsasl session handle
 *
 * Return value: Returns the libgsasl handle given a libgsasl session handle.
 *
 * Deprecated: This function is not useful with the new 0.2.0 API.
 **/
Gsasl *
gsasl_ctx_get (Gsasl_session * sctx)
{
  return sctx->ctx;
}

/**
 * gsasl_encode_inline:
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
 *
 * Deprecated: Use gsasl_encode() instead.
 **/
int
gsasl_encode_inline (Gsasl_session * sctx,
		     const char *input, size_t input_len,
		     char *output, size_t * output_len)
{
  char *tmp;
  size_t tmplen;
  int res;

  res = gsasl_encode (sctx, input, input_len, &tmp, &tmplen);
  if (res == GSASL_OK)
    {
      if (*output_len < tmplen)
	return GSASL_TOO_SMALL_BUFFER;
      *output_len = tmplen;
      memcpy (output, tmp, tmplen);
      free (output);
    }

  return res;
}

/**
 * gsasl_decode_inline:
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
 *
 * Deprecated: Use gsasl_decode() instead.
 **/
int
gsasl_decode_inline (Gsasl_session * sctx,
		     const char *input, size_t input_len,
		     char *output, size_t * output_len)
{
  char *tmp;
  size_t tmplen;
  int res;

  res = gsasl_decode (sctx, input, input_len, &tmp, &tmplen);
  if (res == GSASL_OK)
    {
      if (*output_len < tmplen)
	return GSASL_TOO_SMALL_BUFFER;
      *output_len = tmplen;
      memcpy (output, tmp, tmplen);
      free (output);
    }

  return res;
}

/**
 * gsasl_application_data_set:
 * @ctx: libgsasl handle.
 * @appdata: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl handle.  The
 * application data can be later (for instance, inside a callback) be
 * retrieved by calling gsasl_application_data_get().  It is normally
 * used by the application to maintain state between the main program
 * and the callback.
 *
 * Deprecated: Use gsasl_callback_hook_set() instead.
 **/
void
gsasl_application_data_set (Gsasl * ctx, void *appdata)
{
  ctx->application_hook = appdata;
}

/**
 * gsasl_application_data_get:
 * @ctx: libgsasl handle.
 *
 * Retrieve application specific data from libgsasl handle. The
 * application data is set using gsasl_application_data_set().  It is
 * normally used by the application to maintain state between the main
 * program and the callback.
 *
 * Return value: Returns the application specific data, or NULL.
 *
 * Deprecated: Use gsasl_callback_hook_get() instead.
 **/
void *
gsasl_application_data_get (Gsasl * ctx)
{
  return ctx->application_hook;
}

/**
 * gsasl_appinfo_set:
 * @sctx: libgsasl session handle.
 * @appdata: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl session handle.
 * The application data can be later (for instance, inside a callback)
 * be retrieved by calling gsasl_appinfo_get().  It is normally used
 * by the application to maintain state between the main program and
 * the callback.
 *
 * Deprecated: Use gsasl_callback_hook_set() instead.
 **/
void
gsasl_appinfo_set (Gsasl_session * sctx, void *appdata)
{
  sctx->application_data = appdata;
}

/**
 * gsasl_appinfo_get:
 * @sctx: libgsasl session handle.
 *
 * Retrieve application specific data from libgsasl session
 * handle. The application data is set using gsasl_appinfo_set().  It
 * is normally used by the application to maintain state between the
 * main program and the callback.
 *
 * Return value: Returns the application specific data, or NULL.
 *
 * Deprecated: Use gsasl_callback_hook_get() instead.
 **/
void *
gsasl_appinfo_get (Gsasl_session * sctx)
{
  return sctx->application_data;
}

/**
 * gsasl_server_suggest_mechanism:
 * @ctx: libgsasl handle.
 * @mechlist: input character array with SASL mechanism names,
 *   separated by invalid characters (e.g. SPC).
 *
 * Return value: Returns name of "best" SASL mechanism supported by
 * the libgsasl server which is present in the input string.
 *
 * Deprecated: This function was never useful, since it is the client
 * that chose which mechanism to use.
 **/
const char *
gsasl_server_suggest_mechanism (Gsasl * ctx, const char *mechlist)
{
  return NULL;  /* This function is just silly. */
}
