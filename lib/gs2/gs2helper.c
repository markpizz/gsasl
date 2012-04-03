/* gs2helper.c --- GS2 helper functions common to client and server.
 * Copyright (C) 2010-2012 Simon Josefsson
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

/* Get strcmp. */
#include <string.h>

/* Get malloc, free. */
#include <stdlib.h>

/* Get specification. */
#include "gs2helper.h"

/* Populate mech_oid with OID for the current SASL mechanism name.  A
   bit silly given that we only support Kerberos V5 today, but will be
   useful when that changes.  */
int
gs2_get_oid (Gsasl_session * sctx, gss_OID * mech_oid)
{
  gss_buffer_desc sasl_mech_name;
  OM_uint32 maj_stat, min_stat;

  sasl_mech_name.value = (void *) gsasl_mechanism_name (sctx);
  if (!sasl_mech_name.value)
    return GSASL_AUTHENTICATION_ERROR;
  sasl_mech_name.length = strlen (sasl_mech_name.value);

  maj_stat = gss_inquire_mech_for_saslname (&min_stat, &sasl_mech_name,
					    mech_oid);
  if (GSS_ERROR (maj_stat))
    return GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR;

  return GSASL_OK;
}
