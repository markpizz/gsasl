/* client.c --- SASL mechanism SECURID from RFC 2808, client side.
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
_gsasl_securid_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  Gsasl_ctx *ctx;
  int *step;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_client_callback_authorization_id_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK;

  if (gsasl_client_callback_authentication_id_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

  if (gsasl_client_callback_passcode_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_PASSCODE_CALLBACK;

  step = (int *) malloc (sizeof (*step));
  if (step == NULL)
    return GSASL_MALLOC_ERROR;

  *step = 0;

  *mech_data = step;

  return GSASL_OK;
}

int
_gsasl_securid_client_step (Gsasl_session_ctx * sctx,
			    void *mech_data,
			    const char *input,
			    size_t input_len,
			    char *output, size_t * output_len)
{
  int *step = mech_data;
  Gsasl_client_callback_authorization_id cb_authorization_id;
  Gsasl_client_callback_authentication_id cb_authentication_id;
  Gsasl_client_callback_passcode cb_passcode;
  Gsasl_client_callback_pin cb_pin;
  Gsasl_ctx *ctx;
  int do_pin = 0;
  char *tmp;
  int res;
  size_t len;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_authorization_id = gsasl_client_callback_authorization_id_get (ctx);
  if (cb_authorization_id == NULL)
    return GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK;

  cb_authentication_id = gsasl_client_callback_authentication_id_get (ctx);
  if (cb_authentication_id == NULL)
    return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

  cb_passcode = gsasl_client_callback_passcode_get (ctx);
  if (cb_passcode == NULL)
    return GSASL_NEED_CLIENT_PASSCODE_CALLBACK;

  cb_pin = gsasl_client_callback_pin_get (ctx);

  switch (*step)
    {
    case 1:
      if (input_len == strlen (PASSCODE) &&
	  memcmp (input, PASSCODE, strlen (PASSCODE)) == 0)
	{
	  *step = 0;
	}
      else if (input_len >= strlen (PIN) &&
	       memcmp (input, PIN, strlen (PIN)) == 0)
	{
	  if (cb_pin == NULL)
	    return GSASL_NEED_CLIENT_PIN_CALLBACK;
	  do_pin = 1;
	  *step = 0;
	}
      else
	{
	  *output_len = 0;
	  res = GSASL_OK;
	  break;
	}
      /* fall through */

    case 0:
      tmp = output;
      len = *output_len - (tmp - output) - 1;
      res = cb_authorization_id (sctx, output, &len);
      if (res != GSASL_OK)
	return res;
      tmp[len] = '\0';
      tmp = tmp + len + 1;
      if (*output_len <= (tmp - output))
	return GSASL_TOO_SMALL_BUFFER;
      len = *output_len - (tmp - output) - 1;
      res = cb_authentication_id (sctx, tmp, &len);
      if (res != GSASL_OK)
	return res;
      tmp[len] = '\0';
      tmp = tmp + len + 1;
      if (*output_len <= (tmp - output))
	return GSASL_TOO_SMALL_BUFFER;
      len = *output_len - (tmp - output) - 1;
      res = cb_passcode (sctx, tmp, &len);
      if (res != GSASL_OK)
	return res;
      tmp[len] = '\0';
      tmp = tmp + len + 1;
      if (*output_len <= (tmp - output))
	return GSASL_TOO_SMALL_BUFFER;
      if (do_pin)
	{
	  len = *output_len - (tmp - output);
	  if (input_len > strlen (PIN))
	    {
	      char *zsuggestedpin;

	      zsuggestedpin = malloc (input_len - strlen (PIN) + 1);
	      if (zsuggestedpin == NULL)
		return GSASL_MALLOC_ERROR;
	      memcpy (zsuggestedpin, &input[strlen (PIN)],
		      input_len - strlen (PIN));
	      zsuggestedpin[input_len - strlen (PIN)] = '\0';
	      res = cb_pin (sctx, zsuggestedpin, tmp, &len);
	      free (zsuggestedpin);
	    }
	  else
	    res = cb_pin (sctx, NULL, tmp, &len);
	  if (res != GSASL_OK)
	    return res;
	  tmp[len] = '\0';
	  tmp = tmp + len + 1;
	}

      *output_len = (tmp - output);
      (*step)++;
      res = GSASL_OK;
      break;

    case 2:
      *output_len = 0;
      (*step)++;
      res = GSASL_OK;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

int
_gsasl_securid_client_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  int *step = mech_data;

  free (step);

  return GSASL_OK;
}
