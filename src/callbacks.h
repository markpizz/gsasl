/* callbacks.h	function prototypes for gsasl callbacks
 * Copyright (C) 2002, 2003  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _CALLBACKS_H
#define _CALLBACKS_H

#include <gsasl.h>		/* Gsasl_session_ctx */

/* Client callbacks */

extern int
client_callback_anonymous (Gsasl_session_ctx * ctx,
			   char *out, size_t * outlen);

extern int
client_callback_authorization_id (Gsasl_session_ctx * ctx,
				  char *out, size_t * outlen);

extern int
client_callback_authentication_id (Gsasl_session_ctx * ctx,
				   char *out, size_t * outlen);

extern int
client_callback_password (Gsasl_session_ctx * ctx,
			  char *out, size_t * outlen);

extern int
client_callback_service (Gsasl_session_ctx * ctx,
			 char *srv,
			 size_t * srvlen,
			 char *host,
			 size_t * hostlen,
			 char *srvname, size_t * srvnamelen);

extern int
client_callback_passcode (Gsasl_session_ctx * ctx,
			  char *out, size_t * outlen);

extern Gsasl_qop
client_callback_qop (Gsasl_session_ctx * ctx, Gsasl_qop serverqops);

extern size_t client_callback_maxbuf (Gsasl_session_ctx * ctx,
				      size_t servermaxbuf);

extern int
client_callback_realm (Gsasl_session_ctx * ctx, char *out, size_t * outlen);

/* Server callbacks */

extern int
server_callback_cram_md5 (Gsasl_session_ctx * ctx,
			  char *username, char *challenge, char *response);

extern int
server_callback_anonymous (Gsasl_session_ctx * ctx, const char *message);

extern Gsasl_qop server_callback_qop (Gsasl_session_ctx * ctx);

extern size_t server_callback_maxbuf (Gsasl_session_ctx * ctx);

extern int
server_callback_realm (Gsasl_session_ctx * ctx,
		       char *out, size_t * outlen, size_t nth);

extern int server_callback_external (Gsasl_session_ctx * ctx);

extern int
server_callback_validate (Gsasl_session_ctx * ctx,
			  const char *authorization_id,
			  const char *authentication_id,
			  const char *password);

extern int
server_callback_retrieve (Gsasl_session_ctx * ctx,
			  const char *authentication_id,
			  const char *authorization_id,
			  const char *realm, char *key, size_t * keylen);

extern int
server_callback_service (Gsasl_session_ctx * ctx,
			 char *srv,
			 size_t * srvlen, char *host, size_t * hostlen);

int
server_callback_gssapi (Gsasl_session_ctx * ctx,
			const char *clientname,
			const char *authentication_id);

#endif /* _CALLBACKS_H */
