/* gs2helper.h --- GS2 helper functions for missing GSS-API interface.
 * Copyright (C) 2010  Simon Josefsson
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

/* Get strcmp. */
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

/* Get specification. */
#include "gs2helper.h"

OM_uint32
gss_inquiry_mech_for_saslname (OM_uint32 *minor_status,
			       const gss_buffer_t sasl_mech_name,
			       gss_OID *mech_type)
{
  static const gss_OID_desc krb5oid_static = {
    9, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
  };

  if (sasl_mech_name->value == NULL ||
      strcmp (sasl_mech_name->value, "GS2-KRB5") != 0)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_BAD_MECH;
    }

  if (mech_type)
    *mech_type = &krb5oid_static;

  return GSS_S_COMPLETE;
}
