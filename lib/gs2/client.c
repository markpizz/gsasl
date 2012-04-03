/* client.c --- SASL mechanism GS2, client side.
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

struct _gsasl_gs2_client_state
{
  /* steps: 0 = initial, 1 = first token, 2 = looping, 3 = done */
  int step;
  gss_name_t service;
  gss_ctx_id_t context;
  gss_OID mech_oid;
  gss_buffer_desc token;
  struct gss_channel_bindings_struct cb;
};
typedef struct _gsasl_gs2_client_state _gsasl_gs2_client_state;

/* Initialize GS2 state into MECH_DATA.  Return GSASL_OK if GS2 is
   ready and initialization succeeded, or an error code. */
int
_gsasl_gs2_client_start (Gsasl_session * sctx, void **mech_data)
{
  _gsasl_gs2_client_state *state;
  int res;

  state = (_gsasl_gs2_client_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  res = gs2_get_oid (sctx, &state->mech_oid);
  if (res != GSASL_OK)
    {
      free (state);
      return res;
    }

  state->step = 0;
  state->service = GSS_C_NO_NAME;
  state->context = GSS_C_NO_CONTEXT;
  state->token.length = 0;
  state->token.value = NULL;
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

/* Return newly allocated copy of STR with all occurrences of ','
   replaced with =2C and '=' with '=3D', or return NULL on memory
   allocation errors.  */
static char *
escape_authzid (const char *str)
{
  char *out = malloc (strlen (str) * 3 + 1);
  char *p = out;

  if (!out)
    return NULL;

  while (*str)
    {
      if (*str == ',')
	{
	  memcpy (p, "=2C", 3);
	  p += 3;
	}
      else if (*str == '=')
	{
	  memcpy (p, "=3D", 3);
	  p += 3;
	}
      else
	{
	  *p = *str;
	  p++;
	}
      str++;
    }
  *p = '\0';

  return out;
}

/* Get service, hostname and authorization identity from application,
   import the GSS-API name, and initialize the channel binding data.
   Return GSASL_OK on success or an error code. */
static int
prepare (Gsasl_session * sctx, _gsasl_gs2_client_state * state)
{
  const char *service = gsasl_property_get (sctx, GSASL_SERVICE);
  const char *hostname = gsasl_property_get (sctx, GSASL_HOSTNAME);
  const char *authzid = gsasl_property_get (sctx, GSASL_AUTHZID);
  gss_buffer_desc bufdesc;
  OM_uint32 maj_stat, min_stat;

  if (!service)
    return GSASL_NO_SERVICE;
  if (!hostname)
    return GSASL_NO_HOSTNAME;

  bufdesc.length = asprintf ((char **) &bufdesc.value, "%s@%s",
			     service, hostname);
  if (bufdesc.length <= 0 || bufdesc.value == NULL)
    return GSASL_MALLOC_ERROR;

  maj_stat = gss_import_name (&min_stat, &bufdesc,
			      GSS_C_NT_HOSTBASED_SERVICE, &state->service);
  free (bufdesc.value);
  if (GSS_ERROR (maj_stat))
    return GSASL_GSSAPI_IMPORT_NAME_ERROR;

  if (authzid)
    {
      char *escaped_authzid = escape_authzid (authzid);

      if (!escaped_authzid)
	return GSASL_MALLOC_ERROR;

      state->cb.application_data.length
	= asprintf ((char **) &state->cb.application_data.value,
		    "n,a=%s,", escaped_authzid);

      free (escaped_authzid);
    }
  else
    {
      state->cb.application_data.value = strdup ("n,,");
      state->cb.application_data.length = 3;
    }

  if (state->cb.application_data.length <= 0
      || state->cb.application_data.value == NULL)
    return GSASL_MALLOC_ERROR;

  return GSASL_OK;
}

/* Copy token to output buffer.  On first round trip, strip context
   token header and add channel binding data. For later round trips,
   just copy the buffer.  Return GSASL_OK on success or an error
   code.  */
static int
token2output (Gsasl_session * sctx,
	      _gsasl_gs2_client_state * state,
	      const gss_buffer_t token, char **output, size_t * output_len)
{
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc bufdesc;

  if (state->step == 1)
    {
      state->step++;

      maj_stat = gss_decapsulate_token (token, state->mech_oid, &bufdesc);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR;

      *output_len = state->cb.application_data.length + bufdesc.length;
      *output = malloc (*output_len);
      if (!*output)
	{
	  gss_release_buffer (&min_stat, &bufdesc);
	  return GSASL_MALLOC_ERROR;
	}

      memcpy (*output, state->cb.application_data.value,
	      state->cb.application_data.length);
      memcpy (*output + state->cb.application_data.length,
	      bufdesc.value, bufdesc.length);

      maj_stat = gss_release_buffer (&min_stat, &bufdesc);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_RELEASE_BUFFER_ERROR;
    }
  else
    {
      *output_len = token->length;
      *output = malloc (*output_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, token->value, token->length);
    }

  return GSASL_OK;
}

/* Perform one GS2 step.  GS2 state is in MECH_DATA.  Any data from
   server is provided in INPUT/INPUT_LEN and output from client is
   expected to be put in newly allocated OUTPUT/OUTPUT_LEN.  Return
   GSASL_NEEDS_MORE or GSASL_OK on success, or an error code.  */
int
_gsasl_gs2_client_step (Gsasl_session * sctx,
			void *mech_data,
			const char *input, size_t input_len,
			char **output, size_t * output_len)
{
  _gsasl_gs2_client_state *state = mech_data;
  gss_buffer_desc bufdesc;
  gss_buffer_t buf = GSS_C_NO_BUFFER;
  OM_uint32 maj_stat, min_stat, ret_flags;
  gss_OID actual_mech_type;
  int res;

  if (state->step > 2)
    return GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;

  if (state->step == 0)
    {
      res = prepare (sctx, state);
      if (res != GSASL_OK)
	return res;
      state->step++;
    }

  if (state->step == 2)
    {
      bufdesc.length = input_len;
      bufdesc.value = (void *) input;
      buf = &bufdesc;
    }

  /* First release memory for token from last round-trip, if any. */
  if (state->token.value != NULL)
    {
      maj_stat = gss_release_buffer (&min_stat, &state->token);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_RELEASE_BUFFER_ERROR;

      state->token.value = NULL;
      state->token.length = 0;
    }

  maj_stat = gss_init_sec_context (&min_stat,
				   GSS_C_NO_CREDENTIAL,
				   &state->context,
				   state->service,
				   state->mech_oid,
				   GSS_C_MUTUAL_FLAG,
				   0,
				   &state->cb,
				   buf,
				   &actual_mech_type,
				   &state->token, &ret_flags, NULL);
  if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;

  res = token2output (sctx, state, &state->token, output, output_len);
  if (res != GSASL_OK)
    return res;

  if (maj_stat == GSS_S_CONTINUE_NEEDED)
    return GSASL_NEEDS_MORE;

  /* The GSS-API layer is done here, check that we established a valid
     security context for GS2 purposes. */

  if (!(ret_flags & GSS_C_MUTUAL_FLAG))
    return GSASL_AUTHENTICATION_ERROR;

  if (!gss_oid_equal (state->mech_oid, actual_mech_type))
    return GSASL_AUTHENTICATION_ERROR;

  state->step++;
  return GSASL_OK;
}

/* Cleanup GS2 state context, i.e., release memory associated with
   buffers in MECH_DATA state. */
void
_gsasl_gs2_client_finish (Gsasl_session * sctx, void *mech_data)
{
  _gsasl_gs2_client_state *state = mech_data;
  OM_uint32 maj_stat, min_stat;

  if (!state)
    return;

  if (state->token.value != NULL)
    maj_stat = gss_release_buffer (&min_stat, &state->token);
  if (state->service != GSS_C_NO_NAME)
    maj_stat = gss_release_name (&min_stat, &state->service);
  if (state->context != GSS_C_NO_CONTEXT)
    maj_stat = gss_delete_sec_context (&min_stat, &state->context,
				       GSS_C_NO_BUFFER);

  free (state->cb.application_data.value);
  free (state);
}
