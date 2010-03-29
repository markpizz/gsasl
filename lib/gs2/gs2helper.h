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

#ifndef GS2_HELPER_H
# define GS2_HELPER_H

extern int
gs2_get_oid (Gsasl_session * sctx, gss_OID *mech_oid);

#ifndef HAVE_GSS_INQUIRE_MECH_FOR_SASLNAME
extern OM_uint32
gss_inquiry_mech_for_saslname (OM_uint32 *minor_status,
			       const gss_buffer_t sasl_mech_name,
			       gss_OID *mech_type);
#endif /* HAVE_GSS_INQUIRE_MECH_FOR_SASLNAME */

#ifndef HAVE_GSS_ENCAPSULATE_TOKEN
extern OM_uint32
gss_encapsulate_token (const gss_buffer_t input_token,
		       const gss_OID token_oid,
		       gss_buffer_t output_token);
#endif /* HAVE_GSS_ENCAPSULATE_TOKEN */

#ifndef HAVE_GSS_DECAPSULATE_TOKEN
OM_uint32
gss_decapsulate_token (const gss_buffer_t input_token,
		       const gss_OID token_oid,
		       gss_buffer_t output_token);
#endif

#endif /* GS2_HELPER_H */
