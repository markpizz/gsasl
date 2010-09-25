/* gss-extra.h --- Provide GSS-API symbols when missing from library.
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

#ifndef GSS_EXTRA_H
# define GSS_EXTRA_H

/* Get GSS-API functions. */
#ifdef HAVE_LIBGSS
# include <gss.h>
#elif HAVE_GSSAPI_H
# include <gssapi.h>
#elif HAVE_GSSAPI_GSSAPI_H
# include <gssapi/gssapi.h>
#endif

#ifndef HAVE_GSS_OID_EQUAL
extern int gss_oid_equal (const gss_OID first_oid, const gss_OID second_oid);
#endif /* HAVE_GSS_OID_EQUAL */

#ifndef HAVE_GSS_INQUIRE_MECH_FOR_SASLNAME
OM_uint32
gss_inquire_mech_for_saslname (OM_uint32 * minor_status,
			       const gss_buffer_t sasl_mech_name,
			       gss_OID * mech_type);
#endif /* HAVE_GSS_INQUIRE_MECH_FOR_SASLNAME */

#ifndef HAVE_GSS_ENCAPSULATE_TOKEN
extern OM_uint32
gss_encapsulate_token (const gss_buffer_t input_token,
		       const gss_OID token_oid, gss_buffer_t output_token);
#endif /* HAVE_GSS_ENCAPSULATE_TOKEN */

#ifndef HAVE_GSS_DECAPSULATE_TOKEN
OM_uint32
gss_decapsulate_token (const gss_buffer_t input_token,
		       const gss_OID token_oid, gss_buffer_t output_token);
#endif

#endif /* GSS_EXTRA_H */
