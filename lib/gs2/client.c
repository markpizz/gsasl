/* client.c --- SASL mechanism GS2, client side.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2010  Simon Josefsson
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
#include "gs2asn1.h"

struct _gsasl_gs2_client_state
{
  int step;
  gss_name_t service;
  gss_ctx_id_t context;
  gss_OID mech_oid;
  struct gss_channel_bindings_struct cb;
};
typedef struct _gsasl_gs2_client_state _gsasl_gs2_client_state;

int
_gsasl_gs2_client_start (Gsasl_session * sctx, void **mech_data)
{
  _gsasl_gs2_client_state *state;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc sasl_mech_name;

  state = (_gsasl_gs2_client_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->context = GSS_C_NO_CONTEXT;
  state->service = GSS_C_NO_NAME;
  state->step = 0;

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

  sasl_mech_name.value = (void *) gsasl_mechanism_name (sctx);
  if (!sasl_mech_name.value)
    return GSASL_AUTHENTICATION_ERROR;
  sasl_mech_name.length = strlen (sasl_mech_name.value);

  maj_stat = gss_inquire_mech_for_saslname (&min_stat, &sasl_mech_name,
					    &state->mech_oid);
  if (GSS_ERROR (maj_stat))
    return GSASL_AUTHENTICATION_ERROR;

  *mech_data = state;

  return GSASL_OK;
}

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

int
_gsasl_gs2_client_step (Gsasl_session * sctx,
			void *mech_data,
			const char *input, size_t input_len,
			char **output, size_t * output_len)
{
  _gsasl_gs2_client_state *state = mech_data;
  gss_buffer_desc bufdesc, bufdesc2;
  gss_buffer_t buf = GSS_C_NO_BUFFER;
  OM_uint32 maj_stat, min_stat, ret_flags;
  gss_OID actual_mech_type;
  int res;

  if (state->step == 0)
    {
      const char *service, *hostname;
      const char *authzid = gsasl_property_get (sctx, GSASL_AUTHZID);

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

      maj_stat = gss_import_name (&min_stat, &bufdesc,
				  GSS_C_NT_HOSTBASED_SERVICE,
				  &state->service);
      free (bufdesc.value);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_IMPORT_NAME_ERROR;

      if (authzid)
	{
	  char *escaped_authzid = escape_authzid (authzid);
	  if (!escaped_authzid)
	    return GSASL_MALLOC_ERROR;
	  state->cb.application_data.length
	    = asprintf ((char**) &state->cb.application_data.value,
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
    }

  switch (state->step)
    {
    case 1:
      bufdesc.length = input_len;
      bufdesc.value = (void *) input;
      buf = &bufdesc;
      /* fall through */

    case 0:
      bufdesc2.length = 0;
      bufdesc2.value = NULL;

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
				       &bufdesc2,
				       &ret_flags,
				       NULL);
      if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
	return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;

      /* The mutual_req_flag MUST be set.  Clients MUST check that the
	 corresponding ret_flag is set when the context is fully
	 established, else authentication MUST fail. */
      if (maj_stat == GSS_S_COMPLETE && !(ret_flags & GSS_C_MUTUAL_FLAG))
	return GSASL_AUTHENTICATION_ERROR;

      if (state->mech_oid->length != actual_mech_type->length ||
	  memcmp (state->mech_oid->elements, actual_mech_type->elements,
		  state->mech_oid->length) != 0)
	return GSASL_AUTHENTICATION_ERROR;

      if (state->step == 0)
	{
	  const char *der = bufdesc2.value;
	  size_t derlen = bufdesc2.length;
	  size_t l, ll;

	  /* Strip off RFC 2743 section 3.1 token header. */

	  if (derlen-- == 0)
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  if (*der++ != '\x60')
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  l = gs2_asn1_get_length_der (der, derlen, &ll);
	  if (l <= 0 || derlen <= ll)
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  derlen -= ll;
	  der += ll;
	  if (derlen != l)
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  if (derlen-- == 0)
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  if (*der++ != '\x06')
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  l = gs2_asn1_get_length_der (der, derlen, &ll);
	  if (l <= 0 || derlen <= ll)
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  derlen -= ll;
	  der += ll;
	  if (l != state->mech_oid->length)
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  if (memcmp (state->mech_oid->elements, der, l) != 0)
	    return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;
	  derlen -= l;
	  der += l;

	  *output_len = state->cb.application_data.length + derlen;
	  *output = malloc (*output_len);
	  if (!*output)
	    return GSASL_MALLOC_ERROR;
	  memcpy (*output, state->cb.application_data.value,
		  state->cb.application_data.length);
	  memcpy (*output + state->cb.application_data.length, der, derlen);
	}
      else
	{
	  *output_len = bufdesc2.length;
	  *output = malloc (*output_len);
	  if (!*output)
	    return GSASL_MALLOC_ERROR;
	  memcpy (*output, bufdesc2.value, bufdesc2.length);
	}

      if (state->step == 0 && maj_stat == GSS_S_CONTINUE_NEEDED)
	state->step++;
      if (maj_stat == GSS_S_COMPLETE)
	state->step++;

      if (maj_stat == GSS_S_COMPLETE)
	res = GSASL_OK;
      else
	res = GSASL_NEEDS_MORE;

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

void
_gsasl_gs2_client_finish (Gsasl_session * sctx, void *mech_data)
{
  _gsasl_gs2_client_state *state = mech_data;
  OM_uint32 maj_stat, min_stat;

  if (!state)
    return;

  if (state->service != GSS_C_NO_NAME)
    maj_stat = gss_release_name (&min_stat, &state->service);
  if (state->context != GSS_C_NO_CONTEXT)
    maj_stat = gss_delete_sec_context (&min_stat, &state->context,
				       GSS_C_NO_BUFFER);

  free (state->cb.application_data.value);
  free (state);
}
