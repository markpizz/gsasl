/* internal.h	internal header file for libgsasl
 * Copyright (C) 2002, 2003  Simon Josefsson
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

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#endif

/* Get specifications. */
#include "gsasl.h"

/* I18n of error codes. */
#include "gettext.h"
#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Used by *-md5.c. */
#define HEXCHAR(c) ((c & 0x0F) > 9 ? 'a' + (c & 0x0F) - 10 : '0' + (c & 0x0F))

typedef int (*_Gsasl_code_function) (Gsasl_session_ctx * sctx,
				     void *mech_data,
				     const char *input,
				     size_t input_len,
				     char *output, size_t * output_len);

struct _Gsasl_mechanism_functions
{
  int (*init) (Gsasl_ctx * ctx);
  void (*done) (Gsasl_ctx * ctx);
  int (*start) (Gsasl_session_ctx * sctx, void **mech_data);
  int (*step) (Gsasl_session_ctx * sctx,
	       void *mech_data,
	       const char *input,
	       size_t input_len, char *output, size_t * output_len);
  int (*finish) (Gsasl_session_ctx * sctx, void *mech_data);
  _Gsasl_code_function encode;
  _Gsasl_code_function decode;
};

struct _Gsasl_mechanism
{
  const char *name;

  struct _Gsasl_mechanism_functions client;
  struct _Gsasl_mechanism_functions server;
};
typedef struct _Gsasl_mechanism _Gsasl_mechanism;

extern _Gsasl_mechanism _gsasl_all_mechanisms[];

struct Gsasl_ctx
{
  size_t n_client_mechs;
  _Gsasl_mechanism *client_mechs;
  size_t n_server_mechs;
  _Gsasl_mechanism *server_mechs;
  void *application_data;
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

struct Gsasl_session_ctx
{
  Gsasl_ctx *ctx;
  int clientp;
  _Gsasl_mechanism *mech;
  void *application_data;
  void *mech_data;
};

#ifndef WITH_STRINGPREP
extern char *_gsasl_no_stringprep_nfkc (const char *in, ssize_t len);
extern char *_gsasl_no_stringprep (const char *in, int *stringprep_rc);
#define gsasl_stringprep_nfkc _gsasl_no_stringprep_nfkc
#define gsasl_stringprep_saslprep _gsasl_no_stringprep
#define gsasl_stringprep_trace _gsasl_no_stringprep
#endif

extern int _gsasl_crypto_init (void);
extern int gsasl_randomize (int strong, char *data, size_t datalen);
extern int gsasl_md5 (const char *in, size_t inlen, char *out[16]);
extern int gsasl_hmac_md5 (const char *key, size_t keylen,
			   const char *in, size_t inlen, char *outhash[16]);

#endif /* _INTERNAL_H */
