/* gs2helper.h --- GS2 helper functions common to client and server.
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

#ifndef GS2_HELPER_H
#define GS2_HELPER_H

/* Get GSS-API functions. */
#ifdef HAVE_LIBGSS
#include <gss.h>
#elif HAVE_GSSAPI_H
#include <gssapi.h>
#elif HAVE_GSSAPI_GSSAPI_H
#include <gssapi/gssapi.h>
#endif

/* Get gsasl functions and types. */
#include <gsasl.h>

extern int gs2_get_oid (Gsasl_session * sctx, gss_OID * mech_oid);

#endif /* GS2_HELPER_H */
