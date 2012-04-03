/* openid20.h --- Prototypes for OPENID20.
 * Copyright (C) 2011-2012 Simon Josefsson
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

#ifndef OPENID20_H
#define OPENID20_H

#include <gsasl.h>

#define GSASL_OPENID20_NAME "OPENID20"

extern Gsasl_mechanism gsasl_openid20_mechanism;

extern int _gsasl_openid20_client_start (Gsasl_session * sctx,
					 void **mech_data);

extern int _gsasl_openid20_client_step (Gsasl_session * sctx,
					void *mech_data,
					const char *input, size_t input_len,
					char **output, size_t * output_len);

extern void _gsasl_openid20_client_finish (Gsasl_session * sctx,
					   void *mech_data);

extern int _gsasl_openid20_server_start (Gsasl_session * sctx,
					 void **mech_data);

extern int _gsasl_openid20_server_step (Gsasl_session * sctx,
					void *mech_data,
					const char *input, size_t input_len,
					char **output, size_t * output_len);

extern void _gsasl_openid20_server_finish (Gsasl_session * sctx,
					   void *mech_data);

#endif /* OPENID20_H */
