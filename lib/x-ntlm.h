/* sasl-ntlm.h	header file for non-standard SASL mechanism NTLM
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of libgsasl.
 *
 * Libgsasl is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Libgsasl is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with libgsasl; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _SASL_NTLM_H
#define _SASL_NTLM_H

#ifdef USE_NTLM

#define _GSASL_NTLM_NAME "NTLM"

extern int _gsasl_ntlm_client_init (Gsasl_ctx * ctx);
extern void _gsasl_ntlm_client_done (Gsasl_ctx * ctx);
extern int _gsasl_ntlm_client_start (Gsasl_session_ctx * cctx,
				     void **mech_data);
extern int _gsasl_ntlm_client_step (Gsasl_session_ctx * cctx,
				    void *mech_data,
				    const char *input,
				    size_t input_len,
				    char *output, size_t * output_len);
extern int _gsasl_ntlm_client_finish (Gsasl_session_ctx * cctx,
				      void *mech_data);

extern int _gsasl_ntlm_server_init (Gsasl_ctx * ctx);
extern void _gsasl_ntlm_server_done (Gsasl_ctx * ctx);
extern int _gsasl_ntlm_server_start (Gsasl_session_ctx * sctx,
				     void **mech_data);
extern int _gsasl_ntlm_server_step (Gsasl_session_ctx * sctx,
				    void *mech_data,
				    const char *input,
				    size_t input_len,
				    char *output, size_t * output_len);
extern int _gsasl_ntlm_server_finish (Gsasl_session_ctx * sctx,
				      void *mech_data);
#endif /* USE_NTLM */

#endif /* _SASL_NTLM_H */
