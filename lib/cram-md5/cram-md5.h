/* cram-md5.h --- Prototypes for CRAM-MD5 mechanism as defined in RFC 2195.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
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
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#ifndef _CRAM_MD5_H
#define _CRAM_MD5_H

#include "internal.h"

#define _GSASL_CRAM_MD5_NAME "CRAM-MD5"

extern int _gsasl_cram_md5_client_start (Gsasl_session_ctx * sctx,
					 void **mech_data);
extern int _gsasl_cram_md5_client_step (Gsasl_session_ctx * sctx,
					void *mech_data,
					const char *input,
					size_t input_len,
					char *output, size_t * output_len);
extern int _gsasl_cram_md5_client_finish (Gsasl_session_ctx * sctx,
					  void *mech_data);

extern int _gsasl_cram_md5_server_start (Gsasl_session_ctx * sctx,
					 void **mech_data);
extern int _gsasl_cram_md5_server_step (Gsasl_session_ctx * sctx,
					void *mech_data,
					const char *input,
					size_t input_len,
					char *output, size_t * output_len);
extern int _gsasl_cram_md5_server_finish (Gsasl_session_ctx * sctx,
					  void *mech_data);

#endif /* _CRAM_MD5_H */
