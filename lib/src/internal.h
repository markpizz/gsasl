/* internal.h --- Internal header with hidden library handle structures.
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
 * You should have received a copy of the GNU Lesser General Public License
 * License along with GNU SASL Library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef INTERNAL_H
# define INTERNAL_H

# if HAVE_CONFIG_H
#  include "config.h"
# endif

/* Get specifications. */
# include "gsasl.h"

/* Get malloc, free, ... */
# include <stdlib.h>

/* Get strlen, strcpy, ... */
# include <string.h>

/* Mechanism function prototypes. */
typedef int (*_Gsasl_init_function) (Gsasl * ctx);
typedef void (*_Gsasl_done_function) (Gsasl * ctx);
typedef int (*_Gsasl_start_function) (Gsasl_session * sctx, void **mech_data);
typedef int (*_Gsasl_step_function) (Gsasl_session * sctx,
				     void *mech_data,
				     const char *input, size_t input_len,
				     char *output, size_t * output_len);
typedef int (*_Gsasl_finish_function) (Gsasl_session * sctx, void *mech_data);
typedef int (*_Gsasl_code_function) (Gsasl_session * sctx,
				     void *mech_data,
				     const char *input, size_t input_len,
				     char **output, size_t * output_len);

typedef int (*_Gsasl_step_function_a) (Gsasl_session * sctx, void *mech_data,
				       const char *input, size_t input_len,
				       char **output, size_t * output_len);

/* Collection of mechanism functions for either client or server. */
struct _Gsasl_mechanism_functions
{
  _Gsasl_init_function init;
  _Gsasl_done_function done;
  _Gsasl_start_function start;
  _Gsasl_step_function step;
  _Gsasl_finish_function finish;
  _Gsasl_code_function encode;
  _Gsasl_code_function decode;
  /* New allocating interface. */
  _Gsasl_step_function_a astep;
};

/* Information about a mechanism. */
struct _Gsasl_mechanism
{
  const char *name;

  struct _Gsasl_mechanism_functions client;
  struct _Gsasl_mechanism_functions server;
};
typedef struct _Gsasl_mechanism _Gsasl_mechanism;

/* Move to gsasl.h once all mechanisms have been rewritten to use
   allocating API.  See register.c. */
extern int gsasl_register (Gsasl * ctx, const _Gsasl_mechanism * mech);

/* Main library handle. */
struct Gsasl
{
  size_t n_client_mechs;
  _Gsasl_mechanism *client_mechs;
  size_t n_server_mechs;
  _Gsasl_mechanism *server_mechs;
  void *application_data;
  /* Global callback. */
  Gsasl_callback_function cb;
  /* Global properties. */
  char *anonymous_token;
  char *authid;
  char *authzid;
  char *password;
  /* Obsolete callbacks. */
  Gsasl_client_callback_authorization_id cbc_authorization_id;
  Gsasl_client_callback_authentication_id cbc_authentication_id;
  Gsasl_client_callback_password cbc_password;
  Gsasl_client_callback_passcode cbc_passcode;
  Gsasl_client_callback_pin cbc_pin;
  Gsasl_client_callback_anonymous cbc_anonymous;
  Gsasl_client_callback_qop cbc_qop;
  Gsasl_client_callback_maxbuf cbc_maxbuf;
  Gsasl_client_callback_service cbc_service;
  Gsasl_client_callback_realm cbc_realm;
  Gsasl_server_callback_validate cbs_validate;
  Gsasl_server_callback_securid cbs_securid;
  Gsasl_server_callback_retrieve cbs_retrieve;
  Gsasl_server_callback_cram_md5 cbs_cram_md5;
  Gsasl_server_callback_digest_md5 cbs_digest_md5;
  Gsasl_server_callback_external cbs_external;
  Gsasl_server_callback_anonymous cbs_anonymous;
  Gsasl_server_callback_realm cbs_realm;
  Gsasl_server_callback_qop cbs_qop;
  Gsasl_server_callback_maxbuf cbs_maxbuf;
  Gsasl_server_callback_cipher cbs_cipher;
  Gsasl_server_callback_service cbs_service;
  Gsasl_server_callback_gssapi cbs_gssapi;
};

/* Per-session library handle. */
struct Gsasl_session
{
  Gsasl *ctx;
  int clientp;
  _Gsasl_mechanism *mech;
  void *application_data;
  void *mech_data;
  /* Session specific callback.  If NULL, use global callback in
   * ctx->cb.  */
  Gsasl_callback_function cb;
  /* Session specific properties.  If NULL, use corresponding global
   * property. */
  char *anonymous_token;
  char *authid;
  char *authzid;
  char *password;
};

#endif /* INTERNAL_H */
