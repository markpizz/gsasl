/* callback.c	callback handling
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

#include "internal.h"

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
 * gsasl_application_session_data_set:
 * @sctx: libgsasl session handle.
 * @application_data: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl session handle.
 * The application data can be later (for instance, inside a callback)
 * be retrieved by calling gsasl_application_session_data_get().  It
 * is normally used by the application to maintain state between the
 * main program and the callback.
 **/
void
gsasl_application_session_data_set (Gsasl_session_ctx * sctx,
				    void *application_data)
{
  sctx->application_data = application_data;
}

/**
 * gsasl_client_application_data_get:
 * @sctx: libgsasl client handle.
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
gsasl_application_session_data_get (Gsasl_session_ctx * sctx)
{
  return sctx->application_data;
}
