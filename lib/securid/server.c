/* server.c --- SASL mechanism SECURID from RFC 2808, server side.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#include "securid.h"

#define PASSCODE "passcode"
#define PIN "pin"

int
_gsasl_securid_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  Gsasl_ctx *ctx;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_server_callback_securid_get (ctx) == NULL)
    return GSASL_NEED_SERVER_SECURID_CALLBACK;

  return GSASL_OK;
}

int
_gsasl_securid_server_step (Gsasl_session_ctx * sctx,
			    void *mech_data,
			    const char *input,
			    size_t input_len,
			    char *output, size_t * output_len)
{
  Gsasl_server_callback_securid cb_securid;
  const char *authorization_id = NULL;
  const char *authentication_id = NULL;
  const char *passcode = NULL;
  char *pin = NULL;
  Gsasl_ctx *ctx;
  int res;
  size_t len;

  if (input_len == 0)
    {
      *output_len = 0;
      return GSASL_NEEDS_MORE;
    }

  authorization_id = input;
  authentication_id = memchr (input, '\0', input_len);
  if (authentication_id)
    {
      authentication_id++;
      passcode = memchr (authentication_id, '\0',
			 input_len - strlen (authorization_id) - 1);
      if (passcode)
	{
	  passcode++;
	  pin = memchr (passcode, '\0', input_len -
			strlen (authorization_id) - strlen (passcode) - 1);
	  if (pin)
	    {
	      pin++;
	      if (pin && !*pin)
		pin = NULL;
	    }
	}
    }

  if (passcode == NULL)
    return GSASL_MECHANISM_PARSE_ERROR;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_securid = gsasl_server_callback_securid_get (ctx);
  if (cb_securid == NULL)
    return GSASL_NEED_SERVER_SECURID_CALLBACK;

  len = *output_len;
  res = cb_securid (sctx, authentication_id, authorization_id,
		    passcode, pin, output, &len);
  switch (res)
    {
    case GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE:
      if (*output_len < strlen (PASSCODE))
	return GSASL_TOO_SMALL_BUFFER;
      memcpy (output, PASSCODE, strlen (PASSCODE));
      *output_len = strlen (PASSCODE);
      res = GSASL_NEEDS_MORE;
      break;

    case GSASL_SECURID_SERVER_NEED_NEW_PIN:
      memmove (output + strlen (PIN), output, len);
      memcpy (output, PIN, strlen (PIN));
      *output_len = len + strlen (PIN);
      res = GSASL_NEEDS_MORE;
      break;

    default:
      *output_len = 0;
      break;
    }

  return res;
}
