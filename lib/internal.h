/* internal.h	internal header file for libgsasl
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

#ifndef _INTERNAL_H
#define _INTERNAL_H

#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "config.h"
#include "gsasl.h"
#include "gettext.h"

#ifdef ENABLE_NLS
extern char *_gsasl_gettext (const char *str);
#define _(String) _gsasl_gettext (String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)
#endif

#define HEXCHAR(c) ((c & 0x0F) > 9 ? 'a' + (c & 0x0F) - 10 : '0' + (c & 0x0F))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

struct _Gsasl_mechanism_functions {
  int	(*init)   (Gsasl_ctx *ctx);
  void	(*done)   (Gsasl_ctx *ctx);
  int	(*start)  (Gsasl_session_ctx *cctx, 
		   void **mech_data);
  int	(*step)   (Gsasl_session_ctx *cctx, 
		   void *mech_data, 
		   const char *input, 
		   size_t input_len,
		   char *output, 
		   size_t *output_len);
  int	(*finish) (Gsasl_session_ctx *cctx, 
		   void *mech_data);
};

struct _Gsasl_mechanism {
  char *name;

  struct _Gsasl_mechanism_functions client;
  struct _Gsasl_mechanism_functions server;
};
typedef struct _Gsasl_mechanism _Gsasl_mechanism;

extern _Gsasl_mechanism _gsasl_all_mechanisms[];

struct Gsasl_ctx {
  size_t                                    n_client_mechs;
  _Gsasl_mechanism                          *client_mechs;
  size_t                                    n_server_mechs;
  _Gsasl_mechanism                          *server_mechs;
  void                                      *application_data;
  Gsasl_client_callback_authorization_id    cbc_authorization_id;
  Gsasl_client_callback_authentication_id   cbc_authentication_id;
  Gsasl_client_callback_password            cbc_password;
  Gsasl_client_callback_passcode            cbc_passcode;
  Gsasl_client_callback_pin                 cbc_pin;
  Gsasl_client_callback_anonymous           cbc_anonymous;
  Gsasl_client_callback_qop                 cbc_qop;
  Gsasl_client_callback_maxbuf              cbc_maxbuf;
  Gsasl_client_callback_service             cbc_service;
  Gsasl_server_callback_validate            cbs_validate;
  Gsasl_server_callback_securid             cbs_securid;
  Gsasl_server_callback_retrieve            cbs_retrieve;
  Gsasl_server_callback_cram_md5            cbs_cram_md5;
  Gsasl_server_callback_digest_md5          cbs_digest_md5;
  Gsasl_server_callback_external            cbs_external;
  Gsasl_server_callback_anonymous           cbs_anonymous;
  Gsasl_server_callback_realm               cbs_realm;
  Gsasl_server_callback_qop                 cbs_qop;
  Gsasl_server_callback_maxbuf              cbs_maxbuf;
  Gsasl_server_callback_cipher              cbs_cipher;
  Gsasl_server_callback_service             cbs_service;
  Gsasl_server_callback_gssapi              cbs_gssapi;
};

struct Gsasl_session_ctx {
  Gsasl_ctx *ctx;
  _Gsasl_mechanism *mech;
  void *application_data;
  void *mech_data;
};

#endif /* _INTERNAL_H */
