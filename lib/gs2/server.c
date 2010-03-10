/* server.c --- SASL mechanism GS2, server side.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2010  Simon Josefsson
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "gs2.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

#ifdef HAVE_LIBGSS
# include <gss.h>
#elif HAVE_GSSAPI_H
# include <gssapi.h>
#elif HAVE_GSSAPI_GSSAPI_H
# include <gssapi/gssapi.h>
#endif

#include "gs2helper.h"

struct _Gsasl_gs2_server_state
{
  int step;
  gss_name_t client;
  gss_cred_id_t cred;
  gss_ctx_id_t context;
  gss_OID mech_oid;
  struct gss_channel_bindings_struct cb;
};
typedef struct _Gsasl_gs2_server_state _Gsasl_gs2_server_state;

int
_gsasl_gs2_server_start (Gsasl_session * sctx, void **mech_data)
{
  _Gsasl_gs2_server_state *state;
  OM_uint32 maj_stat, min_stat;
  gss_name_t server;
  gss_buffer_desc bufdesc;
  const char *service;
  const char *hostname;

  service = gsasl_property_get (sctx, GSASL_SERVICE);
  if (!service)
    return GSASL_NO_SERVICE;

  hostname = gsasl_property_get (sctx, GSASL_HOSTNAME);
  if (!hostname)
    return GSASL_NO_HOSTNAME;

  bufdesc.length = asprintf ((char**) &bufdesc.value, "%s@%s",
			     service, hostname);
  if (bufdesc.length <= 0 || bufdesc.value == NULL)
    return GSASL_MALLOC_ERROR;

  state = (_Gsasl_gs2_server_state *) malloc (sizeof (*state));
  if (state == NULL)
    {
      free (bufdesc.value);
      return GSASL_MALLOC_ERROR;
    }

  maj_stat = gss_import_name (&min_stat, &bufdesc, GSS_C_NT_HOSTBASED_SERVICE,
			      &server);
  free (bufdesc.value);
  if (GSS_ERROR (maj_stat))
    {
      free (state);
      return GSASL_GSSAPI_IMPORT_NAME_ERROR;
    }

  maj_stat = gss_acquire_cred (&min_stat, server, 0,
			       GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
			       &state->cred, NULL, NULL);
  gss_release_name (&min_stat, &server);

  if (GSS_ERROR (maj_stat))
    {
      free (state);
      return GSASL_GSSAPI_ACQUIRE_CRED_ERROR;
    }

  {
    gss_buffer_desc sasl_mech_name;

    sasl_mech_name.value = (void *) gsasl_mechanism_name (sctx);
    if (!sasl_mech_name.value)
      return GSASL_AUTHENTICATION_ERROR;
    sasl_mech_name.length = strlen (sasl_mech_name.value);

    maj_stat = gss_inquiry_mech_for_saslname (&min_stat, &sasl_mech_name,
					      &state->mech_oid);
    if (GSS_ERROR (maj_stat))
      return GSASL_AUTHENTICATION_ERROR;
  }

  state->step = 0;
  state->context = GSS_C_NO_CONTEXT;
  state->client = NULL;

  /* The initiator-address-type and acceptor-address-type fields of
     the GSS-CHANNEL-BINDINGS structure MUST be set to 0.  The
     initiator-address and acceptor-address fields MUST be the empty
     string. */
  state->cb.initiator_addrtype = 0;
  state->cb.initiator_address.length = 0;
  state->cb.initiator_address.value = NULL;
  state->cb.acceptor_addrtype = 0;
  state->cb.acceptor_address.length = 0;
  state->cb.acceptor_address.value = NULL;
  state->cb.application_data.length = 0;
  state->cb.application_data.value = NULL;

  *mech_data = state;

  return GSASL_OK;
}

static char *
unescape_authzid (const char *str, size_t len)
{
  char *out = malloc (len + 1);
  char *p = out;

  if (!out)
    return NULL;

  while (len > 0 && *str)
    {
      if (len >= 3 && str[0] == '=' && str[1] == '2' && str[2] == 'C')
	{
	  *p++ = ',';
	  str += 3;
	  len -= 3;
	}
      else if (len >= 3 && str[0] == '=' && str[1] == '3' && str[2] == 'D')
	{
	  *p++ = '=';
	  str += 3;
	  len -= 3;
	}
      else
	{
	  *p++ = *str;
	  str++;
	  len--;
	}
    }
  *p = '\0';

  return out;
}

static int
parse_gs2_header (const char *data, size_t len,
		  char **authzid, size_t *headerlen)
{
  char *authzid_endptr;

  if (len < 3)
    return GSASL_MECHANISM_PARSE_ERROR;

  if (strncmp (data, "n,,", 3) == 0)
    {
      *headerlen = 3;
      *authzid = NULL;
    }
  else if (strncmp (data, "n,a=", 4) == 0 &&
	   (authzid_endptr = memchr (data + 4, ',', len - 4)))
    {
      *authzid = unescape_authzid (data + 4, authzid_endptr - (data + 4));
      if (!*authzid)
	return GSASL_MALLOC_ERROR;
      *headerlen = authzid_endptr - data + 1;
    }
  else
    return GSASL_MECHANISM_PARSE_ERROR;

  return GSASL_OK;
}

int
_gsasl_gs2_server_step (Gsasl_session * sctx,
			void *mech_data,
			const char *input, size_t input_len,
			char **output, size_t * output_len)
{
  _Gsasl_gs2_server_state *state = mech_data;
  gss_buffer_desc bufdesc1, bufdesc2;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc client_name;
  gss_OID mech_type;
  int res;
  OM_uint32 ret_flags;

  *output = NULL;
  *output_len = 0;
  bufdesc1.value = input;
  bufdesc1.length = input_len;

  switch (state->step)
    {
    case 0:
      if (input_len == 0)
	{
	  res = GSASL_NEEDS_MORE;
	  break;
	}
      state->step++;
      /* fall through */

    case 1:
      {
	char *authzid;
	size_t headerlen;

	res = parse_gs2_header (input, input_len, &authzid, &headerlen);
	if (res != GSASL_OK)
	  return res;

	if (authzid)
	  gsasl_property_set (sctx, GSASL_AUTHZID, authzid);

	state->cb.application_data.value = input;
	state->cb.application_data.length = headerlen;

	bufdesc2.value = input + headerlen;
	bufdesc2.length = input_len - headerlen;

	res = gss_encapsulate_token (&bufdesc2, state->mech_oid, &bufdesc1);
	if (res != 1)
	  return res;
      }
      state->step++;
      /* fall through */

    case 2:
      if (state->client)
	{
	  gss_release_name (&min_stat, &state->client);
	  state->client = GSS_C_NO_NAME;
	}

      maj_stat = gss_accept_sec_context (&min_stat,
					 &state->context,
					 state->cred,
					 &bufdesc1,
					 &state->cb,
					 &state->client,
					 &mech_type,
					 &bufdesc2, &ret_flags, NULL, NULL);
      if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
	return GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR;

      *output = malloc (bufdesc2.length);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, bufdesc2.value, bufdesc2.length);
      *output_len = bufdesc2.length;

      maj_stat = gss_release_buffer (&min_stat, &bufdesc2);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_RELEASE_BUFFER_ERROR;

      if (maj_stat == GSS_S_COMPLETE)
	state->step++;

      if (maj_stat == GSS_S_COMPLETE)
	res = GSASL_OK;
      else
	res = GSASL_NEEDS_MORE;
      break;

    case 3:
      maj_stat = gss_display_name (&min_stat, state->client,
				   &client_name, &mech_type);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_DISPLAY_NAME_ERROR;

      gsasl_property_set_raw (sctx, GSASL_GSSAPI_DISPLAY_NAME,
			      client_name.value, client_name.length);

      res = gsasl_callback (NULL, sctx, GSASL_VALIDATE_GSSAPI);

      state->step++;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

void
_gsasl_gs2_server_finish (Gsasl_session * sctx, void *mech_data)
{
  _Gsasl_gs2_server_state *state = mech_data;
  OM_uint32 min_stat;

  if (!state)
    return;

  if (state->context != GSS_C_NO_CONTEXT)
    gss_delete_sec_context (&min_stat, &state->context, GSS_C_NO_BUFFER);

  if (state->cred != GSS_C_NO_CREDENTIAL)
    gss_release_cred (&min_stat, &state->cred);

  if (state->client != GSS_C_NO_NAME)
    gss_release_name (&min_stat, &state->client);

  free (state);
}
