/* property.c --- Callback property handling.
 * Copyright (C) 2004  Simon Josefsson
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

static char **
map (Gsasl_session * sctx, Gsasl_property prop)
{
  char **p = NULL;

  if (!sctx)
    return NULL;

  switch (prop)
    {
    case GSASL_CLIENT_ANONYMOUS:
    case GSASL_SERVER_ANONYMOUS:
      p = &sctx->anonymous_token;
      break;

    case GSASL_AUTHID:
      p = &sctx->authid;
      break;

    case GSASL_AUTHZID:
      p = &sctx->authzid;
      break;

    case GSASL_PASSWORD:
      p = &sctx->password;
      break;

    case GSASL_PASSCODE:
      p = &sctx->passcode;
      break;

    case GSASL_PIN:
      p = &sctx->pin;
      break;

    case GSASL_SUGGESTED_PIN:
      p = &sctx->suggestedpin;
      break;

    default:
      break;
    }

  return p;
}

static char **
map_global (Gsasl * ctx, Gsasl_property prop)
{
  char **p = NULL;

  if (!ctx)
    return NULL;

  switch (prop)
    {
    case GSASL_CLIENT_ANONYMOUS:
    case GSASL_SERVER_ANONYMOUS:
      p = &ctx->anonymous_token;
      break;

    case GSASL_AUTHID:
      p = &ctx->authid;
      break;

    case GSASL_AUTHZID:
      p = &ctx->authzid;
      break;

    case GSASL_PASSWORD:
      p = &ctx->password;
      break;

    case GSASL_PASSCODE:
      p = &ctx->passcode;
      break;

    case GSASL_PIN:
      p = &ctx->pin;
      break;

    case GSASL_SUGGESTED_PIN:
      p = &ctx->suggestedpin;
      break;

    default:
      break;
    }

  return p;
}

/**
 * gsasl_property_set:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 * @data: zero terminated character string to store.
 *
 * Make a copy of @data and store it in the session handle for the
 * indicated property @prop.  You can immediately deallocate @data
 * after calling this function, without affecting the data stored in
 * the session handle.
 *
 * It is valid, but may be confusing at first, to store both session
 * specific properties, using gsasl_property_set(), and more global
 * library handle properties using gsasl_property_set_global(), at the
 * same time.  The functions gsasl_property_get() and
 * gsasl_property_fast() will fall back to the global variables if no
 * session specific data is present.
 **/
void
gsasl_property_set (Gsasl_session * sctx, Gsasl_property prop,
		    const char *data)
{
  char **p = map (sctx, prop);

  if (p)
    {
      if (*p)
	free (*p);
      if (data)
	*p = strdup (data);
      else
	*p = NULL;
    }
}

/**
 * gsasl_property_set_global:
 * @ctx: library handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 * @data: zero terminated character string to store.
 *
 * Make a copy of @data and store it in the library handle for the
 * indicated property @prop.  You can immediately deallocate @data
 * after calling this function, without affecting the data stored in
 * the session handle.
 *
 * It is valid, but may be confusing at first, to store both session
 * specific properties, using gsasl_property_set(), and more global
 * library handle properties using gsasl_property_set_global(), at the
 * same time.  The functions gsasl_property_get() and
 * gsasl_property_fast() will fall back to the global variables if no
 * session specific data is present.
 **/
void
gsasl_property_set_global (Gsasl * ctx, Gsasl_property prop, const char *data)
{
  char **p = map_global (ctx, prop);

  if (p)
    {
      if (*p)
	free (*p);
      if (data)
	*p = strdup (data);
      else
	*p = NULL;
    }
}

/**
 * gsasl_property_fast_global:
 * @ctx: library handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 *
 * Retrieve the data stored in the library handle for given property
 * @prop.  The pointer is to live data, and must not be deallocated or
 * modified in any way.
 *
 * This function will not invoke the application callback if a value
 * is not already known.
 *
 * Return value: Return data for property, or NULL if no value known.
 **/
const char *
gsasl_property_fast_global (Gsasl * ctx, Gsasl_property prop)
{
  char **p = map_global (ctx, prop);

  if (p && *p)
    return *p;

  return NULL;
}

/**
 * gsasl_property_fast:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 *
 * Retrieve the data stored in the session handle for given property
 * @prop.  The pointer is to live data, and must not be deallocated or
 * modified in any way.
 *
 * This function will not invoke the application callback if a value
 * is not already known.
 *
 * Return value: Return data for property, or NULL if no value known.
 **/
const char *
gsasl_property_fast (Gsasl_session * sctx, Gsasl_property prop)
{
  char **p = map (sctx, prop);

  if (p && *p)
    return *p;

  return gsasl_property_fast_global (sctx->ctx, prop);
}

/**
 * gsasl_property_get:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 *
 * Retrieve the data stored in the session handle for given property
 * @prop, possibly invoking the application callback to get the value.
 * The pointer is to live data, and must not be deallocated or
 * modified in any way.
 *
 * This function will invoke the application callback, using
 * gsasl_callback(), if a value is not already known.
 *
 * If no value is known, and no callback is specified or if the
 * callback fail to return data, and if the obsolete callback
 * interface has been used by the application, this function will
 * translate the old callback interface into the new.  This interface
 * should be sufficient to get data from all callbacks, both new and
 * old.
 *
 * Return value: Return data for property, or NULL if no value known.
 **/
const char *
gsasl_property_get (Gsasl_session * sctx, Gsasl_property prop)
{
  const char *p = gsasl_property_fast (sctx, prop);

  if (!p)
    {
      gsasl_callback (NULL, sctx, prop);
      p = gsasl_property_fast (sctx, prop);
    }

  if (!p)
    {
      Gsasl_client_callback_anonymous cb_anonymous;
      Gsasl_client_callback_authorization_id cb_authorization_id;
      Gsasl_client_callback_authentication_id cb_authentication_id;
      Gsasl_client_callback_password cb_password;
      Gsasl_client_callback_passcode cb_passcode;
      Gsasl_client_callback_pin cb_pin;
      char buf[BUFSIZ];
      size_t buflen = BUFSIZ - 1;
      int res;

      /* Call obsolete callbacks to get properties.  Remove this when
       * the obsolete callbacks are no longer supported. */

      switch (prop)
	{
	case GSASL_CLIENT_ANONYMOUS:
	  cb_anonymous = gsasl_client_callback_anonymous_get (sctx->ctx);
	  if (!cb_anonymous)
	    break;
	  res = cb_anonymous (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_AUTHID:
	  cb_authentication_id =
	    gsasl_client_callback_authentication_id_get (sctx->ctx);
	  if (!cb_authentication_id)
	    break;
	  res = cb_authentication_id (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_AUTHZID:
	  cb_authorization_id =
	    gsasl_client_callback_authorization_id_get (sctx->ctx);
	  if (!cb_authorization_id)
	    break;
	  res = cb_authorization_id (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_PASSWORD:
	  cb_password = gsasl_client_callback_password_get (sctx->ctx);
	  if (!cb_password)
	    break;
	  res = cb_password (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_PASSCODE:
	  cb_passcode = gsasl_client_callback_passcode_get (sctx->ctx);
	  if (!cb_passcode)
	    break;
	  res = cb_passcode (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_PIN:
	  cb_pin = gsasl_client_callback_pin_get (sctx->ctx);
	  if (!cb_pin)
	    break;
	  res = cb_pin (sctx, sctx->suggestedpin, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	default:
	  break;
	}
      p = gsasl_property_fast (sctx, prop);
    }

  return p;
}

/**
 * gsasl_property_get_global:
 * @ctx: library handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 *
 * Retrieve the data stored in the library handle for given property
 * @prop, possibly invoking the application callback to get the value.
 * The pointer is to live data, and must not be deallocated or
 * modified in any way.
 *
 * This function will invoke the application callback, using
 * gsasl_callback_global(), if a value is not already known.
 *
 * Return value: Return data for property, or NULL if no value known.
 **/
const char *
gsasl_property_get_global (Gsasl * ctx, Gsasl_property prop)
{
  const char *p = gsasl_property_fast_global (ctx, prop);

  if (!p)
    {
      gsasl_callback (ctx, NULL, prop);
      p = gsasl_property_fast_global (ctx, prop);
    }

  return p;
}
