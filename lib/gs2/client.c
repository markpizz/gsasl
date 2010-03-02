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
#elif HAVE_GSSAPI_H		/* Heimdal GSSAPI */
# include <gssapi.h>
#else /* MIT GSSAPI */
# ifdef HAVE_GSSAPI_GSSAPI_H
#  include <gssapi/gssapi.h>
# endif
# ifdef HAVE_GSSAPI_GSSAPI_GENERIC_H
#  include <gssapi/gssapi_generic.h>
# endif
#endif

#include "gs2parser.h"
#include "gs2helper.h"

struct _gsasl_gs2_client_state
{
  int step;
  gss_name_t service;
  gss_ctx_id_t context;
  gss_OID mech_oid;
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

  sasl_mech_name.value = (void *) gsasl_mechanism_name (sctx);
  if (!sasl_mech_name.value)
    return GSASL_AUTHENTICATION_ERROR;
  sasl_mech_name.length = strlen (sasl_mech_name.value);

  maj_stat = gss_inquiry_mech_for_saslname (&min_stat, &sasl_mech_name,
					    &state->mech_oid);
  if (GSS_ERROR (maj_stat))
    return GSASL_AUTHENTICATION_ERROR;

  *mech_data = state;

  return GSASL_OK;
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
  OM_uint32 maj_stat, min_stat;
  int res;

  if (state->service == NULL)
    {
      const char *service, *hostname;

      service = gsasl_property_get (sctx, GSASL_SERVICE);
      if (!service)
	return GSASL_NO_SERVICE;

      hostname = gsasl_property_get (sctx, GSASL_HOSTNAME);
      if (!hostname)
	return GSASL_NO_HOSTNAME;

      /* FIXME: Use asprintf. */

      bufdesc.length = strlen (service) + 1 + strlen (hostname) + 1;
      bufdesc.value = malloc (bufdesc.length);
      if (bufdesc.value == NULL)
	return GSASL_MALLOC_ERROR;

      sprintf (bufdesc.value, "%s@%s", service, hostname);

      maj_stat = gss_import_name (&min_stat, &bufdesc,
				  GSS_C_NT_HOSTBASED_SERVICE,
				  &state->service);
      free (bufdesc.value);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_IMPORT_NAME_ERROR;
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
      {
	gss_OID actual_mech_type;
	maj_stat = gss_init_sec_context (&min_stat,
					 GSS_C_NO_CREDENTIAL,
					 &state->context,
					 state->service,
					 state->mech_oid,
					 GSS_C_MUTUAL_FLAG |
					 GSS_C_INTEG_FLAG |
					 GSS_C_CONF_FLAG,
					 0,
					 GSS_C_NO_CHANNEL_BINDINGS,
					 buf,
					 &actual_mech_type,
					 &bufdesc2,
					 NULL, /* ret_flags irrelevant */
					 NULL);
	if (state->mech_oid->length != actual_mech_type->length ||
	    memcmp (state->mech_oid->elements, actual_mech_type->elements,
		    state->mech_oid->length) != 0)
	  return GSASL_AUTHENTICATION_ERROR;
      }
      if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
	return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;

      if (buf == GSS_C_NO_BUFFER)
	{
	  *output_len = bufdesc2.length + 5;
	  *output = malloc (*output_len);
	  if (!*output)
	    return GSASL_MALLOC_ERROR;
	  memcpy (*output + 5, bufdesc2.value, bufdesc2.length);
	  memcpy (*output, "fooba", 5);
	}
      else
	{
	  *output_len = bufdesc2.length;
	  *output = malloc (*output_len);
	  if (!*output)
	    return GSASL_MALLOC_ERROR;
	  memcpy (*output, bufdesc2.value, bufdesc2.length);
	}

      if (maj_stat == GSS_S_COMPLETE)
	{
	  state->step++;
	  res = GSASL_OK;
	}
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

  free (state);
}
