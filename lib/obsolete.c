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
 * Note that this function is obsolete and may be removed in the
 * future.
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
	{
	  free (tmp);
	  return GSASL_TOO_SMALL_BUFFER;
	}

      if (out)
	strcpy (out, tmp);
      *outlen = tmplen;
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
 * Note that this function is obsolete and may be removed in the
 * future.
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
	{
	  free (tmp);
	  return GSASL_TOO_SMALL_BUFFER;
	}

      if (out)
	strcpy (out, tmp);
      *outlen = tmplen;
      free (tmp);
    }

  return rc;
}

static int
_gsasl_step (Gsasl_session_ctx * sctx,
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
 * Note that this function is obsolete and may be removed in the
 * future.
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
 * Note that this function is obsolete and may be removed in the
 * future.
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
  return _gsasl_step (sctx, input, input_len, output, output_len);
}

static int
_gsasl_step64 (Gsasl_session_ctx * sctx,
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
 * Note that this function is obsolete and may be removed in the
 * future.
 *
 * Return value: See gsasl_client_step().
 **/
int
gsasl_client_step_base64 (Gsasl_session_ctx * sctx,
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
 * Note that this function is obsolete and may be removed in the
 * future.
 *
 * Return value: See gsasl_server_step().
 **/
int
gsasl_server_step_base64 (Gsasl_session_ctx * sctx,
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
 * Note that this function is obsolete and may be removed in the
 * future.
 **/
void
gsasl_client_finish (Gsasl_session_ctx * sctx)
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
 * Note that this function is obsolete and may be removed in the
 * future.
 **/
void
gsasl_server_finish (Gsasl_session_ctx * sctx)
{
  gsasl_finish (sctx);
}

/**
 * gsasl_client_ctx_get:
 * @sctx: libgsasl client handle
 *
 * Note that this function is obsolete and may be removed in the
 * future.
 *
 * Return value: Returns the libgsasl handle given a libgsasl client handle.
 **/
Gsasl_ctx *
gsasl_client_ctx_get (Gsasl_session_ctx * sctx)
{
  return gsasl_ctx_get (sctx);
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
 * Note that this function is obsolete and may be removed in the
 * future.
 **/
void
gsasl_client_application_data_set (Gsasl_session_ctx * sctx,
				   void *application_data)
{
  return gsasl_appinfo_set (sctx, application_data);
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
 * Note that this function is obsolete and may be removed in the
 * future.
 *
 * Return value: Returns the application specific data, or NULL.
 **/
void *
gsasl_client_application_data_get (Gsasl_session_ctx * sctx)
{
  return gsasl_appinfo_get (sctx);
}

/**
 * gsasl_server_ctx_get:
 * @sctx: libgsasl server handle
 *
 * Note that this function is obsolete and may be removed in the
 * future.
 *
 * Return value: Returns the libgsasl handle given a libgsasl server handle.
 **/
Gsasl_ctx *
gsasl_server_ctx_get (Gsasl_session_ctx * sctx)
{
  return gsasl_ctx_get (sctx);
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
 * Note that this function is obsolete and may be removed in the
 * future.
 **/
void
gsasl_server_application_data_set (Gsasl_session_ctx * sctx,
				   void *application_data)
{
  return gsasl_appinfo_set (sctx, application_data);
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
 * Note that this function is obsolete and may be removed in the
 * future.
 *
 * Return value: Returns the application specific data, or NULL.
 **/
void *
gsasl_server_application_data_get (Gsasl_session_ctx * sctx)
{
  return gsasl_appinfo_get (sctx);
}
