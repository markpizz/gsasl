/* scram.h --- Prototypes for SCRAM mechanism
 * Copyright (C) 2009-2012 Simon Josefsson
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

#ifndef SCRAM_H
#define SCRAM_H

#include <gsasl.h>

#define GSASL_SCRAM_SHA1_NAME "SCRAM-SHA-1"
#define GSASL_SCRAM_SHA1_PLUS_NAME "SCRAM-SHA-1-PLUS"

extern Gsasl_mechanism gsasl_scram_sha1_mechanism;
extern Gsasl_mechanism gsasl_scram_sha1_plus_mechanism;

int _gsasl_scram_sha1_client_start (Gsasl_session * sctx, void **mech_data);

int
_gsasl_scram_sha1_plus_client_start (Gsasl_session * sctx, void **mech_data);

int
_gsasl_scram_sha1_client_step (Gsasl_session * sctx,
			       void *mech_data,
			       const char *input, size_t input_len,
			       char **output, size_t * output_len);

void _gsasl_scram_sha1_client_finish (Gsasl_session * sctx, void *mech_data);


int _gsasl_scram_sha1_server_start (Gsasl_session * sctx, void **mech_data);

int
_gsasl_scram_sha1_plus_server_start (Gsasl_session * sctx, void **mech_data);

int
_gsasl_scram_sha1_server_step (Gsasl_session * sctx,
			       void *mech_data,
			       const char *input,
			       size_t input_len,
			       char **output, size_t * output_len);

void _gsasl_scram_sha1_server_finish (Gsasl_session * sctx, void *mech_data);

#endif /* SCRAM_H */
