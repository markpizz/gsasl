/* kerberos_v5.h	header file for experimental SASL mechanism KERBEROS_V5
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _KERBEROS_V5_H
#define _KERBEROS_V5_H

#include "internal.h"

#ifdef USE_KERBEROS_V5

#define _GSASL_KERBEROS_V5_NAME "KERBEROS_V5"

extern int _gsasl_kerberos_v5_client_init (Gsasl_ctx * ctx);
extern void _gsasl_kerberos_v5_client_done (Gsasl_ctx * ctx);
extern int _gsasl_kerberos_v5_client_start (Gsasl_session_ctx * sctx,
					    void **mech_data);
extern int _gsasl_kerberos_v5_client_step (Gsasl_session_ctx * sctx,
					   void *mech_data,
					   const char *input,
					   size_t input_len,
					   char *output,
					   size_t * output_len);
extern int _gsasl_kerberos_v5_client_finish (Gsasl_session_ctx * sctx,
					     void *mech_data);

extern int _gsasl_kerberos_v5_server_init (Gsasl_ctx * ctx);
extern void _gsasl_kerberos_v5_server_done (Gsasl_ctx * ctx);
extern int _gsasl_kerberos_v5_server_start (Gsasl_session_ctx * sctx,
					    void **mech_data);
extern int _gsasl_kerberos_v5_server_step (Gsasl_session_ctx * sctx,
					   void *mech_data,
					   const char *input,
					   size_t input_len,
					   char *output,
					   size_t * output_len);
extern int _gsasl_kerberos_v5_server_finish (Gsasl_session_ctx * sctx,
					     void *mech_data);

#endif /* USE_KERBEROS_V5 */

#endif /* _KERBEROS_V5_H */
