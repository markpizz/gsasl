/* ntlm.c	implementation of non-standard SASL mechanism NTLM
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

#ifdef USE_NTLM

#include <ntlm.h>

struct _Gsasl_ntlm_state
{
  int step;
  char *username;
};
typedef struct _Gsasl_ntlm_state _Gsasl_ntlm_state;

int
_gsasl_ntlm_client_init (Gsasl_ctx * ctx)
{
  return GSASL_OK;
}

void
_gsasl_ntlm_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_ntlm_client_start (Gsasl_session_ctx * cctx, void **mech_data)
{
  _Gsasl_ntlm_state *state;
  Gsasl_ctx *ctx;

  ctx = gsasl_client_ctx_get (cctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_client_callback_authorization_id_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK;

  if (gsasl_client_callback_password_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  state = (_Gsasl_ntlm_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;
  state->username = NULL;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_ntlm_client_step (Gsasl_session_ctx * cctx,
			 void *mech_data,
			 const char *input,
			 size_t input_len, char *output, size_t * output_len)
{
  _Gsasl_ntlm_state *state = mech_data;
  tSmbNtlmAuthRequest request;
  tSmbNtlmAuthChallenge challenge;
  tSmbNtlmAuthResponse response;
  Gsasl_client_callback_authorization_id cb_authorization_id;
  Gsasl_client_callback_password cb_password;
  Gsasl_ctx *ctx;
  /* XXX create callback for domain? Doesn't seem to be needed by servers */
  char *domain = NULL;
  char *password;
  size_t len;
  int res;

  ctx = gsasl_client_ctx_get (cctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_authorization_id = gsasl_client_callback_authorization_id_get (ctx);
  if (cb_authorization_id == NULL)
    return GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK;

  cb_password = gsasl_client_callback_password_get (ctx);
  if (cb_password == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  switch (state->step)
    {
    case 0:
      /* Isn't this just the IMAP continuation char?  Not part of SASL mech.
	 if (input_len != 1 && *input != '+')
	 return GSASL_MECHANISM_PARSE_ERROR; */

      len = *output_len;
      res = cb_authorization_id (cctx, NULL, &len);
      if (res != GSASL_OK)
	return res;
      state->username = malloc(len + 1);
      res = cb_authorization_id (cctx, state->username, &len);
      if (res != GSASL_OK)
	return res;
      state->username[len] = '\0';

      buildSmbNtlmAuthRequest (&request, state->username, domain);

      if (*output_len < SmbLength (&request))
	return GSASL_TOO_SMALL_BUFFER;

      *output_len = SmbLength (&request);
      memcpy (output, &request, *output_len);

      /* dumpSmbNtlmAuthRequest(stdout, &request); */

      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 1:
      if (input_len > sizeof (challenge))
	return GSASL_MECHANISM_PARSE_ERROR;

      /* Hand crafted challenge for parser testing:
         TlRMTVNTUAAAAAAAAAAAAAAAAAAAAGFiY2RlZmdoMDEyMzQ1Njc4ODY2NDQwMTIz */

      memcpy (&challenge, input, input_len);

      len = *output_len;
      res = cb_password (cctx, NULL, &len);
      if (res != GSASL_OK)
	return res;
      password = malloc(len + 1);
      res = cb_password (cctx, password, &len);
      if (res != GSASL_OK)
	return res;
      password[len] = '\0';

      buildSmbNtlmAuthResponse (&challenge, &response, state->username,
				password);

      if (*output_len < SmbLength (&response))
	return GSASL_TOO_SMALL_BUFFER;

      *output_len = SmbLength (&response);
      memcpy (output, &response, *output_len);

      /* dumpSmbNtlmAuthResponse(stdout, &response); */

      state->step++;
      res = GSASL_OK;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

int
_gsasl_ntlm_client_finish (Gsasl_session_ctx * cctx, void *mech_data)
{
  _Gsasl_ntlm_state *state = mech_data;

  if (state->username)
    free (state->username);

  free (state);

  return GSASL_OK;
}

#endif /* USE_NTLM */
