/* server.c --- SASL mechanism GS2, server side.
 * Copyright (C) 2002-2012 Simon Josefsson
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
#include "config.h"
#endif

/* Get specification. */
#include "gs2.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

#include "gss-extra.h"
#include "gs2helper.h"
#include "mechtools.h"

struct _Gsasl_gs2_server_state
{
  /* steps: 0 = first state, 1 = initial, 2 = processing, 3 = done */
  int step;
  gss_name_t client;
  gss_cred_id_t cred;
  gss_ctx_id_t context;
  gss_OID mech_oid;
  struct gss_channel_bindings_struct cb;
};
typedef struct _Gsasl_gs2_server_state _Gsasl_gs2_server_state;

/* Populate state->cred with credential to use for connection.  Return
   GSASL_OK on success or an error code.  */
static int
gs2_get_cred (Gsasl_session * sctx, _Gsasl_gs2_server_state * state)
{
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc bufdesc;
  const char *service = gsasl_property_get (sctx, GSASL_SERVICE);
  const char *hostname = gsasl_property_get (sctx, GSASL_HOSTNAME);
  gss_name_t server;
  gss_OID_set_desc oid_set;
  gss_OID_set actual_mechs;
  int present;

  if (!service)
    return GSASL_NO_SERVICE;
  if (!hostname)
    return GSASL_NO_HOSTNAME;

  bufdesc.length = asprintf ((char **) &bufdesc.value, "%s@%s",
			     service, hostname);
  if (bufdesc.length <= 0 || bufdesc.value == NULL)
    return GSASL_MALLOC_ERROR;

  maj_stat = gss_import_name (&min_stat, &bufdesc,
			      GSS_C_NT_HOSTBASED_SERVICE, &server);
  free (bufdesc.value);
  if (GSS_ERROR (maj_stat))
    return GSASL_GSSAPI_IMPORT_NAME_ERROR;

  /* Attempt to get a credential for our mechanism.  */

  oid_set.count = 1;
  oid_set.elements = state->mech_oid;

  maj_stat = gss_acquire_cred (&min_stat, server, 0,
			       &oid_set, GSS_C_ACCEPT,
			       &state->cred, &actual_mechs, NULL);
  gss_release_name (&min_stat, &server);
  if (GSS_ERROR (maj_stat))
    return GSASL_GSSAPI_ACQUIRE_CRED_ERROR;

  /* Now double check that the credential actually was for our
     mechanism... */

  maj_stat = gss_test_oid_set_member (&min_stat, state->mech_oid,
				      actual_mechs, &present);
  if (GSS_ERROR (maj_stat))
    {
      gss_release_oid_set (&min_stat, &actual_mechs);
      return GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR;
    }

  maj_stat = gss_release_oid_set (&min_stat, &actual_mechs);
  if (GSS_ERROR (maj_stat))
    return GSASL_GSSAPI_RELEASE_OID_SET_ERROR;

  if (!present)
    return GSASL_GSSAPI_ACQUIRE_CRED_ERROR;

  return GSASL_OK;
}

/* Initialize GS2 state into MECH_DATA.  Return GSASL_OK if GS2 is
   ready and initialization succeeded, or an error code. */
int
_gsasl_gs2_server_start (Gsasl_session * sctx, void **mech_data)
{
  _Gsasl_gs2_server_state *state;
  int res;

  state = (_Gsasl_gs2_server_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  res = gs2_get_oid (sctx, &state->mech_oid);
  if (res != GSASL_OK)
    {
      free (state);
      return res;
    }

  res = gs2_get_cred (sctx, state);
  if (res != GSASL_OK)
    {
      free (state);
      return res;
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

/* Perform one GS2 step.  GS2 state is in MECH_DATA.  Any data from
   client is provided in INPUT/INPUT_LEN and output from server is
   expected to be put in newly allocated OUTPUT/OUTPUT_LEN.  Return
   GSASL_NEEDS_MORE or GSASL_OK on success, or an error code.  */
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
  int free_bufdesc1 = 0;

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

	res = _gsasl_parse_gs2_header (input, input_len,
				       &authzid, &headerlen);
	if (res != GSASL_OK)
	  return res;

	if (authzid)
	  {
	    gsasl_property_set (sctx, GSASL_AUTHZID, authzid);
	    free (authzid);
	  }

	state->cb.application_data.value = input;
	state->cb.application_data.length = headerlen;

	bufdesc2.value = input + headerlen;
	bufdesc2.length = input_len - headerlen;

	maj_stat = gss_encapsulate_token (&bufdesc2, state->mech_oid,
					  &bufdesc1);
	if (GSS_ERROR (maj_stat))
	  return GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR;

	free_bufdesc1 = 1;
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

      if (maj_stat == GSS_S_COMPLETE)
	{
	  state->step++;

	  if (!(ret_flags & GSS_C_MUTUAL_FLAG))
	    return GSASL_MECHANISM_PARSE_ERROR;

	  maj_stat = gss_display_name (&min_stat, state->client,
				       &client_name, &mech_type);
	  if (GSS_ERROR (maj_stat))
	    return GSASL_GSSAPI_DISPLAY_NAME_ERROR;

	  gsasl_property_set_raw (sctx, GSASL_GSSAPI_DISPLAY_NAME,
				  client_name.value, client_name.length);

	  res = gsasl_callback (NULL, sctx, GSASL_VALIDATE_GSSAPI);
	}
      else
	res = GSASL_NEEDS_MORE;

      if (free_bufdesc1)
	{
	  maj_stat = gss_release_buffer (&min_stat, &bufdesc1);
	  if (GSS_ERROR (maj_stat))
	    return GSASL_GSSAPI_RELEASE_BUFFER_ERROR;
	}

      *output = malloc (bufdesc2.length);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, bufdesc2.value, bufdesc2.length);
      *output_len = bufdesc2.length;

      maj_stat = gss_release_buffer (&min_stat, &bufdesc2);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_RELEASE_BUFFER_ERROR;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

/* Cleanup GS2 state context, i.e., release memory associated with
   buffers in MECH_DATA state. */
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
