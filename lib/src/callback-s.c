/* callback-s.c	--- Callback handling (for servers).
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

#include "internal.h"

/**
 * gsasl_server_callback_validate_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server for deciding if
 * user is authenticated using authentication identity, authorization
 * identity and password.  The function can be later retrieved using
 * gsasl_server_callback_validate_get().
 **/
void
gsasl_server_callback_validate_set (Gsasl * ctx,
				    Gsasl_server_callback_validate cb)
{
  ctx->cbs_validate = cb;
}

/**
 * gsasl_server_callback_validate_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_validate_set().
 **/
Gsasl_server_callback_validate
gsasl_server_callback_validate_get (Gsasl * ctx)
{
  return ctx->cbs_validate;
}

/**
 * gsasl_server_callback_retrieve_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server for deciding if
 * user is authenticated using authentication identity, authorization
 * identity and password.  The function can be later retrieved using
 * gsasl_server_callback_retrieve_get().
 **/
void
gsasl_server_callback_retrieve_set (Gsasl * ctx,
				    Gsasl_server_callback_retrieve cb)
{
  ctx->cbs_retrieve = cb;
}

/**
 * gsasl_server_callback_retrieve_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_retrieve_set().
 **/
Gsasl_server_callback_retrieve
gsasl_server_callback_retrieve_get (Gsasl * ctx)
{
  return ctx->cbs_retrieve;
}

/**
 * gsasl_server_callback_cram_md5_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server for deciding if
 * user is authenticated using CRAM-MD5 challenge and response.  The
 * function can be later retrieved using
 * gsasl_server_callback_cram_md5_get().
 **/
void
gsasl_server_callback_cram_md5_set (Gsasl * ctx,
				    Gsasl_server_callback_cram_md5 cb)
{
  ctx->cbs_cram_md5 = cb;
}

/**
 * gsasl_server_callback_cram_md5_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_cram_md5_set().
 **/
Gsasl_server_callback_cram_md5
gsasl_server_callback_cram_md5_get (Gsasl * ctx)
{
  return ctx->cbs_cram_md5;
}

/**
 * gsasl_server_callback_digest_md5_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server for retrieving
 * the secret hash of the username, realm and password for use in the
 * DIGEST-MD5 mechanism.  The function can be later retrieved using
 * gsasl_server_callback_digest_md5_get().
 **/
void
gsasl_server_callback_digest_md5_set (Gsasl * ctx,
				      Gsasl_server_callback_digest_md5 cb)
{
  ctx->cbs_digest_md5 = cb;
}

/**
 * gsasl_server_callback_digest_md5_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Return the callback earlier set by calling
 * gsasl_server_callback_digest_md5_set().
 **/
Gsasl_server_callback_digest_md5
gsasl_server_callback_digest_md5_get (Gsasl * ctx)
{
  return ctx->cbs_digest_md5;
}

/**
 * gsasl_server_callback_external_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server for deciding if
 * user is authenticated out of band.  The function can be later
 * retrieved using gsasl_server_callback_external_get().
 **/
void
gsasl_server_callback_external_set (Gsasl * ctx,
				    Gsasl_server_callback_external cb)
{
  ctx->cbs_external = cb;
}

/**
 * gsasl_server_callback_external_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_external_set().
 **/
Gsasl_server_callback_external
gsasl_server_callback_external_get (Gsasl * ctx)
{
  return ctx->cbs_external;
}

/**
 * gsasl_server_callback_anonymous_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server for deciding if
 * user is permitted anonymous access.  The function can be later
 * retrieved using gsasl_server_callback_anonymous_get().
 **/
void
gsasl_server_callback_anonymous_set (Gsasl * ctx,
				     Gsasl_server_callback_anonymous cb)
{
  ctx->cbs_anonymous = cb;
}

/**
 * gsasl_server_callback_anonymous_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_anonymous_set().
 **/
Gsasl_server_callback_anonymous
gsasl_server_callback_anonymous_get (Gsasl * ctx)
{
  return ctx->cbs_anonymous;
}

/**
 * gsasl_server_callback_realm_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server to know which
 * realm it serves.  The realm is used by the user to determine which
 * username and password to use.  The function can be later retrieved
 * using gsasl_server_callback_realm_get().
 **/
void
gsasl_server_callback_realm_set (Gsasl * ctx, Gsasl_server_callback_realm cb)
{
  ctx->cbs_realm = cb;
}

/**
 * gsasl_server_callback_realm_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_realm_set().
 **/
Gsasl_server_callback_realm
gsasl_server_callback_realm_get (Gsasl * ctx)
{
  return ctx->cbs_realm;
}

/**
 * gsasl_server_callback_qop_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server to know which
 * quality of protection it accepts.  The quality of protection
 * eventually used is selected by the client though.  It is currently
 * used by the DIGEST-MD5 mechanism. The function can be later
 * retrieved using gsasl_server_callback_qop_get().
 **/
void
gsasl_server_callback_qop_set (Gsasl * ctx, Gsasl_server_callback_qop cb)
{
  ctx->cbs_qop = cb;
}

/**
 * gsasl_server_callback_qop_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_qop_set().
 **/
Gsasl_server_callback_qop
gsasl_server_callback_qop_get (Gsasl * ctx)
{
  return ctx->cbs_qop;
}

/**
 * gsasl_server_callback_maxbuf_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server to inform the
 * client of the largest buffer the server is able to receive when
 * using the DIGEST-MD5 "auth-int" or "auth-conf" Quality of
 * Protection (qop). If this directive is missing, the default value
 * 65536 will be assumed.  The function can be later retrieved using
 * gsasl_server_callback_maxbuf_get().
 **/
void
gsasl_server_callback_maxbuf_set (Gsasl * ctx,
				  Gsasl_server_callback_maxbuf cb)
{
  ctx->cbs_maxbuf = cb;
}

/**
 * gsasl_server_callback_maxbuf_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_maxbuf_set().
 **/
Gsasl_server_callback_maxbuf
gsasl_server_callback_maxbuf_get (Gsasl * ctx)
{
  return ctx->cbs_maxbuf;
}

/**
 * gsasl_server_callback_cipher_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server to inform the
 * client of the cipher suites supported.  The DES and 3DES ciphers
 * must be supported for interoperability.  It is currently used by
 * the DIGEST-MD5 mechanism.  The function can be later retrieved
 * using gsasl_server_callback_cipher_get().
 **/
void
gsasl_server_callback_cipher_set (Gsasl * ctx,
				  Gsasl_server_callback_cipher cb)
{
  ctx->cbs_cipher = cb;
}

/**
 * gsasl_server_callback_cipher_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_cipher_set().
 **/
Gsasl_server_callback_cipher
gsasl_server_callback_cipher_get (Gsasl * ctx)
{
  return ctx->cbs_cipher;
}

/**
 * gsasl_server_callback_securid_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server for validating a
 * user via the SECURID mechanism.  The function should return
 * GSASL_OK if user authenticated successfully,
 * GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE if it wants another
 * passcode, GSASL_SECURID_SERVER_NEED_NEW_PIN if it wants a PIN
 * change, or an error.  When (and only when)
 * GSASL_SECURID_SERVER_NEED_NEW_PIN is returned, suggestpin can be
 * populated with a PIN code the server suggests, and suggestpinlen
 * set to the length of the PIN.  The function can be later retrieved
 * using gsasl_server_callback_securid_get().
 **/
void
gsasl_server_callback_securid_set (Gsasl * ctx,
				   Gsasl_server_callback_securid cb)
{
  ctx->cbs_securid = cb;
}

/**
 * gsasl_server_callback_securid_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_securid_set().
 **/
Gsasl_server_callback_securid
gsasl_server_callback_securid_get (Gsasl * ctx)
{
  return ctx->cbs_securid;
}

/**
 * gsasl_server_callback_gssapi_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server for checking if
 * a GSSAPI user is authorized for username (by, e.g., calling
 * krb5_userok()).  The function should return GSASL_OK if the user
 * should be permitted access, or an error code such as
 * GSASL_AUTHENTICATION_ERROR on failure.  The function can be later
 * retrieved using gsasl_server_callback_gssapi_get().
 **/
void
gsasl_server_callback_gssapi_set (Gsasl * ctx,
				  Gsasl_server_callback_gssapi cb)
{
  ctx->cbs_gssapi = cb;
}

/**
 * gsasl_server_callback_gssapi_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_gssapi_set().
 **/
Gsasl_server_callback_gssapi
gsasl_server_callback_gssapi_get (Gsasl * ctx)
{
  return ctx->cbs_gssapi;
}

/**
 * gsasl_server_callback_service_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the server to set the name
 * of the service.  The service buffer should be a registered GSSAPI
 * host-based service name, hostname the name of the server.  The
 * function can be later retrieved using
 * gsasl_server_callback_service_get().
 **/
void
gsasl_server_callback_service_set (Gsasl * ctx,
				   Gsasl_server_callback_service cb)
{
  ctx->cbs_service = cb;
}

/**
 * gsasl_server_callback_service_get:
 * @ctx: libgsasl handle.
 *
 * Return value: Returns the callback earlier set by calling
 * gsasl_server_callback_service_set().
 **/
Gsasl_server_callback_service
gsasl_server_callback_service_get (Gsasl * ctx)
{
  return ctx->cbs_service;
}
