/* callback.c	callback handling
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

/**
 * gsasl_client_ctx_get:
 * @cctx: libgsasl client handle
 *
 * Return value: Returns the libgsasl handle given a libgsasl client handle.
 **/
Gsasl_ctx *
gsasl_client_ctx_get (Gsasl_session_ctx * cctx)
{
  return cctx->ctx;
}

/**
 * gsasl_server_ctx_get:
 * @cctx: libgsasl server handle
 *
 * Return value: Returns the libgsasl handle given a libgsasl server handle.
 **/
Gsasl_ctx *
gsasl_server_ctx_get (Gsasl_session_ctx * sctx)
{
  return sctx->ctx;
}

/**
 * gsasl_application_data_set:
 * @ctx: libgsasl handle.
 * @application_data: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl handle.  The
 * application data can be later (for instance, inside a callback) be
 * retrieved by calling gsasl_application_data_get().  It is normally
 * used by the application to maintain state between the main program
 * and the callback.
 **/
void
gsasl_application_data_set (Gsasl_ctx * ctx, void *application_data)
{
  ctx->application_data = application_data;
}

/**
 * gsasl_application_data_get:
 * @ctx: libgsasl handle.
 *
 * Retrieve application specific data from libgsasl handle. The
 * application data is set using gsasl_application_data_set().  It is
 * normally used by the application to maintain state between the main
 * program and the callback.
 *
 * Return value: Returns the application specific data, or NULL.
 **/
void *
gsasl_application_data_get (Gsasl_ctx * ctx)
{
  return ctx->application_data;
}

/**
 * gsasl_client_application_data_set:
 * @xctx: libgsasl client handle.
 * @application_data: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl client handle.  The
 * application data can be later (for instance, inside a callback) be
 * retrieved by calling gsasl_client_application_data_get().  It is
 * normally used by the application to maintain state between the main
 * program and the callback.
 **/
void
gsasl_client_application_data_set (Gsasl_session_ctx * cctx,
				   void *application_data)
{
  cctx->application_data = application_data;
}

/**
 * gsasl_client_application_data_get:
 * @xctx: libgsasl client handle.
 *
 * Retrieve application specific data from libgsasl client handle. The
 * application data is set using gsasl_client_application_data_set().
 * It is normally used by the application to maintain state between
 * the main program and the callback.
 *
 * Return value: Returns the application specific data, or NULL.
 **/
void *
gsasl_client_application_data_get (Gsasl_session_ctx * cctx)
{
  return cctx->application_data;
}

/**
 * gsasl_server_application_data_set:
 * @xctx: libgsasl server handle.
 * @application_data: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl server handle.  The
 * application data can be later (for instance, inside a callback) be
 * retrieved by calling gsasl_server_application_data_get().  It is
 * normally used by the application to maintain state between the main
 * program and the callback.
 **/
void
gsasl_server_application_data_set (Gsasl_session_ctx * sctx,
				   void *application_data)
{
  sctx->application_data = application_data;
}

/**
 * gsasl_server_application_data_get:
 * @xctx: libgsasl server handle.
 *
 * Retrieve application specific data from libgsasl server handle. The
 * application data is set using gsasl_server_application_data_set().
 * It is normally used by the application to maintain state between
 * the main program and the callback.
 *
 * Return value: Returns the application specific data, or NULL.
 **/
void *
gsasl_server_application_data_get (Gsasl_session_ctx * sctx)
{
  return sctx->application_data;
}


/*
 *
 ************************* Client Callbacks
 *
 */


/**
 * gsasl_client_callback_authentication_id_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to set the
 * authentication identity.  The function can be later retrieved using
 * gsasl_client_callback_authentication_id_get().
 **/
void
gsasl_client_callback_authentication_id_set (Gsasl_ctx * ctx,
					     Gsasl_client_callback_authentication_id
					     cb)
{
  ctx->cbc_authentication_id = cb;
}

/**
 * gsasl_client_callback_authentication_id_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_authentication_id_set().
 **/
Gsasl_client_callback_authentication_id
gsasl_client_callback_authentication_id_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_authentication_id;
}

/**
 * gsasl_client_callback_authorization_id_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to set the
 * authorization identity.  The function can be later retrieved using
 * gsasl_client_callback_authorization_id_get().
 **/
void
gsasl_client_callback_authorization_id_set (Gsasl_ctx * ctx,
					    Gsasl_client_callback_authorization_id
					    cb)
{
  ctx->cbc_authorization_id = cb;
}

/**
 * gsasl_client_callback_authorization_id_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_authorization_id_set().
 **/
Gsasl_client_callback_authorization_id
gsasl_client_callback_authorization_id_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_authorization_id;
}

/**
 * gsasl_client_callback_password_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to set the
 * password.  The function can be later retrieved using
 * gsasl_client_callback_password_get().
 **/
void
gsasl_client_callback_password_set (Gsasl_ctx * ctx,
				    Gsasl_client_callback_password cb)
{
  ctx->cbc_password = cb;
}


/**
 * gsasl_client_callback_password_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_password_set().
 **/
Gsasl_client_callback_password
gsasl_client_callback_password_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_password;
}

/**
 * gsasl_client_callback_passcode_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to set the
 * passcode.  The function can be later retrieved using
 * gsasl_client_callback_passcode_get().
 **/
void
gsasl_client_callback_passcode_set (Gsasl_ctx * ctx,
				    Gsasl_client_callback_passcode cb)
{
  ctx->cbc_passcode = cb;
}


/**
 * gsasl_client_callback_passcode_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_passcode_set().
 **/
Gsasl_client_callback_passcode
gsasl_client_callback_passcode_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_passcode;
}

/**
 * gsasl_client_callback_pin_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to chose a new
 * pin, possibly suggested by the server, for the SECURID mechanism.
 * This is not normally invoked, but only when the server requests it.
 * The function can be later retrieved using
 * gsasl_client_callback_pin_get().
 **/
void
gsasl_client_callback_pin_set (Gsasl_ctx * ctx, Gsasl_client_callback_pin cb)
{
  ctx->cbc_pin = cb;
}


/**
 * gsasl_client_callback_pin_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_pin_set().
 **/
Gsasl_client_callback_pin
gsasl_client_callback_pin_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_pin;
}

/**
 * gsasl_client_callback_service_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to set the name
 * of the service.  The service buffer should be a registered GSSAPI
 * host-based service name, hostname the name of the server.
 * Servicename is used by DIGEST-MD5 and should be the name of generic
 * server in case of a replicated service. The function can be later
 * retrieved using gsasl_client_callback_service_get().
 **/
void
gsasl_client_callback_service_set (Gsasl_ctx * ctx,
				   Gsasl_client_callback_service cb)
{
  ctx->cbc_service = cb;
}

/**
 * gsasl_client_callback_service_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_service_set().
 **/
Gsasl_client_callback_service
gsasl_client_callback_service_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_service;
}

/**
 * gsasl_client_callback_anonymous_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to set the
 * anonymous token, which usually is the users email address.  The
 * function can be later retrieved using
 * gsasl_client_callback_anonymous_get().
 **/
void
gsasl_client_callback_anonymous_set (Gsasl_ctx * ctx,
				     Gsasl_client_callback_anonymous cb)
{
  ctx->cbc_anonymous = cb;
}

/**
 * gsasl_client_callback_anonymous_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_anonymous_set().
 **/
Gsasl_client_callback_anonymous
gsasl_client_callback_anonymous_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_anonymous;
}

/**
 * gsasl_client_callback_qop_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to determine the
 * qop to use after looking at what the server offered.  The function
 * can be later retrieved using gsasl_client_callback_qop_get().
 **/
void
gsasl_client_callback_qop_set (Gsasl_ctx * ctx, Gsasl_client_callback_qop cb)
{
  ctx->cbc_qop = cb;
}

/**
 * gsasl_client_callback_qop_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_qop_set().
 **/
Gsasl_client_callback_qop
gsasl_client_callback_qop_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_qop;
}

/**
 * gsasl_client_callback_maxbuf_set:
 * @ctx: libgsasl handle.
 * @cb: callback function
 *
 * Specify the callback function to use in the client to inform the
 * server of the largest buffer the client is able to receive when
 * using the DIGEST-MD5 "auth-int" or "auth-conf" Quality of
 * Protection (qop). If this directive is missing, the default value
 * 65536 will be assumed.  The function can be later retrieved using
 * gsasl_client_callback_maxbuf_get().
 **/
void
gsasl_client_callback_maxbuf_set (Gsasl_ctx * ctx,
				  Gsasl_client_callback_maxbuf cb)
{
  ctx->cbc_maxbuf = cb;
}

/**
 * gsasl_client_callback_maxbuf_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_client_callback_maxbuf_set().
 **/
Gsasl_client_callback_maxbuf
gsasl_client_callback_maxbuf_get (Gsasl_ctx * ctx)
{
  return ctx->cbc_maxbuf;
}


/*
 *
 ************************* Server Callbacks
 *
 */


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
gsasl_server_callback_validate_set (Gsasl_ctx * ctx,
				    Gsasl_server_callback_validate cb)
{
  ctx->cbs_validate = cb;
}

/**
 * gsasl_server_callback_validate_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_validate_set().
 **/
Gsasl_server_callback_validate
gsasl_server_callback_validate_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_retrieve_set (Gsasl_ctx * ctx,
				    Gsasl_server_callback_retrieve cb)
{
  ctx->cbs_retrieve = cb;
}

/**
 * gsasl_server_callback_retrieve_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_retrieve_set().
 **/
Gsasl_server_callback_retrieve
gsasl_server_callback_retrieve_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_cram_md5_set (Gsasl_ctx * ctx,
				    Gsasl_server_callback_cram_md5 cb)
{
  ctx->cbs_cram_md5 = cb;
}

/**
 * gsasl_server_callback_cram_md5_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_cram_md5_set().
 **/
Gsasl_server_callback_cram_md5
gsasl_server_callback_cram_md5_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_digest_md5_set (Gsasl_ctx * ctx,
				      Gsasl_server_callback_digest_md5 cb)
{
  ctx->cbs_digest_md5 = cb;
}

/**
 * gsasl_server_callback_digest_md5_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_digest_md5_set().
 **/
Gsasl_server_callback_digest_md5
gsasl_server_callback_digest_md5_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_external_set (Gsasl_ctx * ctx,
				    Gsasl_server_callback_external cb)
{
  ctx->cbs_external = cb;
}

/**
 * gsasl_server_callback_external_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_external_set().
 **/
Gsasl_server_callback_external
gsasl_server_callback_external_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_anonymous_set (Gsasl_ctx * ctx,
				     Gsasl_server_callback_anonymous cb)
{
  ctx->cbs_anonymous = cb;
}

/**
 * gsasl_server_callback_anonymous_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_anonymous_set().
 **/
Gsasl_server_callback_anonymous
gsasl_server_callback_anonymous_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_realm_set (Gsasl_ctx * ctx,
				 Gsasl_server_callback_realm cb)
{
  ctx->cbs_realm = cb;
}

/**
 * gsasl_server_callback_realm_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_realm_set().
 **/
Gsasl_server_callback_realm
gsasl_server_callback_realm_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_qop_set (Gsasl_ctx * ctx, Gsasl_server_callback_qop cb)
{
  ctx->cbs_qop = cb;
}

/**
 * gsasl_server_callback_qop_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_qop_set().
 **/
Gsasl_server_callback_qop
gsasl_server_callback_qop_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_maxbuf_set (Gsasl_ctx * ctx,
				  Gsasl_server_callback_maxbuf cb)
{
  ctx->cbs_maxbuf = cb;
}

/**
 * gsasl_server_callback_maxbuf_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_maxbuf_set().
 **/
Gsasl_server_callback_maxbuf
gsasl_server_callback_maxbuf_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_cipher_set (Gsasl_ctx * ctx,
				  Gsasl_server_callback_cipher cb)
{
  ctx->cbs_cipher = cb;
}

/**
 * gsasl_server_callback_cipher_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_cipher_set().
 **/
Gsasl_server_callback_cipher
gsasl_server_callback_cipher_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_securid_set (Gsasl_ctx * ctx,
				   Gsasl_server_callback_securid cb)
{
  ctx->cbs_securid = cb;
}

/**
 * gsasl_server_callback_securid_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_securid_set().
 **/
Gsasl_server_callback_securid
gsasl_server_callback_securid_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_gssapi_set (Gsasl_ctx * ctx,
				  Gsasl_server_callback_gssapi cb)
{
  ctx->cbs_gssapi = cb;
}

/**
 * gsasl_server_callback_gssapi_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_gssapi_set().
 **/
Gsasl_server_callback_gssapi
gsasl_server_callback_gssapi_get (Gsasl_ctx * ctx)
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
gsasl_server_callback_service_set (Gsasl_ctx * ctx,
				   Gsasl_server_callback_service cb)
{
  ctx->cbs_service = cb;
}

/**
 * gsasl_server_callback_service_get:
 * @ctx: libgsasl handle.
 *
 * Return the callback earlier set by calling
 * gsasl_server_callback_service_set().
 **/
Gsasl_server_callback_service
gsasl_server_callback_service_get (Gsasl_ctx * ctx)
{
  return ctx->cbs_service;
}
