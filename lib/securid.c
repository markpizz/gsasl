/* securid.c	implementation of SASL mechanism SECURID as defined in RFC 2808
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

#ifdef USE_SECURID

int
_gsasl_securid_client_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_securid_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_securid_client_start (Gsasl_session_ctx * cctx, void **mech_data)
{
  Gsasl_ctx *ctx;
  int *step;

  ctx = gsasl_client_ctx_get (cctx);
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

#define PASSCODE "passcode"
#define PIN "pin"

int
_gsasl_securid_client_step (Gsasl_session_ctx * cctx,
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

  ctx = gsasl_client_ctx_get (cctx);
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
      len = *output_len - (tmp - output);
      res = cb_authorization_id (cctx, output, &len);
      if (res != GSASL_OK)
	return res;
      tmp[len] = '\0';
      tmp = tmp + len + 1;
      len = *output_len - (tmp - output);
      res = cb_authentication_id (cctx, tmp, &len);
      if (res != GSASL_OK)
	return res;
      tmp[len] = '\0';
      tmp = tmp + len + 1;
      len = *output_len - (tmp - output);
      res = cb_passcode (cctx, tmp, &len);
      if (res != GSASL_OK)
	return res;
      tmp[len] = '\0';
      tmp = tmp + len + 1;
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
	      res = cb_pin (cctx, zsuggestedpin, tmp, &len);
	      free (zsuggestedpin);
	    }
	  else
	    res = cb_pin (cctx, NULL, tmp, &len);
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
_gsasl_securid_client_finish (Gsasl_session_ctx * cctx, void *mech_data)
{
  int *step = mech_data;

  free (step);

  return GSASL_OK;
}

/* Server */

int
_gsasl_securid_server_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_securid_server_done (Gsasl_ctx * ctx)
{
  return;
}

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

int
_gsasl_securid_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  return GSASL_OK;
}

#endif /* USE_SECURID */
