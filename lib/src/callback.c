/* callback.c --- Callback handling.
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
 * gsasl_callback_set:
 * @sctx: session handle.
 * @cb: pointer to function implemented by application.
 *
 * Store the pointer to the application provided callback in the
 * session specific handle.  The callback will be used, via
 * gsasl_callback(), by mechanisms to discover various parameters
 * (such as username and passwords).  The callback function will be
 * called with a Gsasl_property value indicating the requested
 * behaviour.  For example, for GSASL_CLIENT_ANONYMOUS, the function
 * is expected to invoke gsasl_property_set(SCTX,
 * GSASL_CLIENT_ANONYMOUS, "token") where "token" is the anonymous
 * token the application wishes the SASL mechanism to use.  See the
 * manual for the meaning of all parameters.
 *
 * It is valid, but may be confusing at first, to set different
 * callbacks using gsasl_callback_set() and
 * gsasl_callback_set_global().  Normally the session specific
 * callback (i.e., the one set by gsasl_callback_set()) will be used
 * by mechanisms, with a fall back to the global callback if a session
 * specific callback has not been set.  You can use this to set a
 * general global callback handler that apply to most sessions, but
 * for some specific sessions you can override the callback with a
 * different function.
 **/
void
gsasl_callback_set (Gsasl_session * sctx, Gsasl_callback_function cb)
{
  sctx->cb = cb;
}

/**
 * gsasl_callback_set_global:
 * @ctx: handle received from gsasl_init().
 * @cb: pointer to function implemented by application.
 *
 * Store the pointer to the application provided callback in the
 * library handle.  The callback will be used, via gsasl_callback()
 * and gsasl_callback_global(), by mechanisms to discover various
 * parameters (such as username and passwords).  The callback function
 * will be called with a Gsasl_property value indicating the requested
 * behaviour.  For example, for GSASL_CLIENT_ANONYMOUS, the function
 * is expected to invoke gsasl_property_set_global(CTX,
 * GSASL_CLIENT_ANONYMOUS, "token") where "token" is the anonymous
 * token the application wishes the SASL mechanism to use.  See the
 * manual for the meaning of all parameters.
 *
 * It is valid, but may be confusing at first, to set different
 * callbacks using gsasl_callback_set() and
 * gsasl_callback_set_global().  Normally the session specific
 * callback (i.e., the one set by gsasl_callback_set()) will be used
 * by mechanisms, with a fall back to the global callback if a session
 * specific callback has not been set.  You can use this to set a
 * general global callback handler that apply to most sessions, but
 * for some specific sessions you can override the callback with a
 * different function.
 **/
void
gsasl_callback_set_global (Gsasl * ctx, Gsasl_callback_function cb)
{
  ctx->cb = cb;
}

/**
 * gsasl_callback:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type.
 *
 * Invoke the session specific application callback, with a fall back
 * to the global callback.  The @prop value indicate what the callback
 * is expected to do.  For example, for GSASL_CLIENT_ANONYMOUS, the
 * function is expected to invoke gsasl_property_set(SCTX,
 * GSASL_CLIENT_ANONYMOUS, "token") where "token" is the anonymous
 * token the application wishes the SASL mechanism to use.  See the
 * manual for the meaning of all parameters.
 *
 * Note that if no callback has been set by the application, but the
 * obsolete callback interface has been used, this function will
 * translate the old callback interface into the new.  This interface
 * should be sufficient to invoke all callbacks, both new and old.
 *
 * Return value: Returns whatever the application callback return, or
 *   GSASL_NO_CALLBACK if no application was known.
 **/
int
gsasl_callback (Gsasl_session * sctx, Gsasl_property prop)
{
  if (sctx->cb)
    return sctx->cb (sctx->ctx, sctx, prop);

  if (sctx->ctx->cb)
    return gsasl_callback_global (sctx->ctx, prop);

  {
    /* Call obsolete callbacks.  Remove this when the obsolete
     * callbacks are no longer supported.  This is done here, not in
     * gsasl_callback_global, since all obsolete callbacks were
     * session specific.  */
    Gsasl_server_callback_anonymous cb_anonymous;
    Gsasl_server_callback_external cb_external;
    int res;

    switch (prop)
      {
      case GSASL_SERVER_ANONYMOUS:
	if (!sctx->anonymous_token)
	  break;
	cb_anonymous = gsasl_server_callback_anonymous_get (sctx->ctx);
	if (!cb_anonymous)
	  break;
	res = cb_anonymous (sctx, sctx->anonymous_token);
	return res;
	break;

      case GSASL_SERVER_EXTERNAL:
	cb_external = gsasl_server_callback_external_get (sctx->ctx);
	if (!cb_external)
	  break;
	res = cb_external (sctx);
	return res;
	break;

      default:
	break;
      }
  }

  return GSASL_NO_CALLBACK;
}

/**
 * gsasl_callback_global:
 * @ctx: handle received from gsasl_init().
 * @prop: enumerated value of Gsasl_property type.
 *
 * Invoke the handle global application callback.  The @prop value
 * indicate what the callback is expected to do.  For example, for
 * GSASL_CLIENT_ANONYMOUS, the function is expected to invoke
 * gsasl_property_set(SCTX, GSASL_CLIENT_ANONYMOUS, "token") where
 * "token" is the anonymous token the application wishes the SASL
 * mechanism to use.  See the manual for the meaning of all
 * parameters.
 *
 * Return value: Returns whatever the application callback return, or
 *   GSASL_NO_CALLBACK if no application was known.
 **/
int
gsasl_callback_global (Gsasl * ctx, Gsasl_property prop)
{
  if (ctx->cb)
    return ctx->cb (ctx, NULL, prop);

  return GSASL_NO_CALLBACK;
}

/**
 * gsasl_ctx_get:
 * @sctx: libgsasl session handle
 *
 * Return value: Returns the libgsasl handle given a libgsasl session handle.
 **/
Gsasl *
gsasl_ctx_get (Gsasl_session * sctx)
{
  return sctx->ctx;
}

/**
 * gsasl_application_data_set:
 * @ctx: libgsasl handle.
 * @appdata: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl handle.  The
 * application data can be later (for instance, inside a callback) be
 * retrieved by calling gsasl_application_data_get().  It is normally
 * used by the application to maintain state between the main program
 * and the callback.
 **/
void
gsasl_application_data_set (Gsasl * ctx, void *appdata)
{
  ctx->application_data = appdata;
}

/**
 * gsasl_application_data_get:
 * @ctx: libgsasl handle.
 *
 * Retrieve application specific data from libgsasl handle. The
 * application data is set using gsasl_appdata_set().  It is
 * normally used by the application to maintain state between the main
 * program and the callback.
 *
 * Return value: Returns the application specific data, or NULL.
 **/
void *
gsasl_application_data_get (Gsasl * ctx)
{
  return ctx->application_data;
}

/**
 * gsasl_appinfo_set:
 * @sctx: libgsasl session handle.
 * @appdata: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl session handle.
 * The application data can be later (for instance, inside a callback)
 * be retrieved by calling gsasl_application_session_data_get().  It
 * is normally used by the application to maintain state between the
 * main program and the callback.
 **/
void
gsasl_appinfo_set (Gsasl_session * sctx, void *appdata)
{
  sctx->application_data = appdata;
}

/**
 * gsasl_appinfo_get:
 * @sctx: libgsasl session handle.
 *
 * Retrieve application specific data from libgsasl session
 * handle. The application data is set using
 * gsasl_application_session_data_set().  It is normally used by the
 * application to maintain state between the main program and the
 * callback.
 *
 * Return value: Returns the application specific data, or NULL.
 **/
void *
gsasl_appinfo_get (Gsasl_session * sctx)
{
  return sctx->application_data;
}
