/* init.c --- Entry point for libgsasl.
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

/* Get gc_init. */
#include <gc.h>

/* See common.c. */
extern _Gsasl_mechanism _gsasl_all_mechanisms[];

/**
 * gsasl_init:
 * @ctx: pointer to libgsasl handle.
 *
 * This functions initializes libgsasl.  The handle pointed to by ctx
 * is valid for use with other libgsasl functions iff this function is
 * successful.
 *
 * Return value: GSASL_OK iff successful, otherwise GSASL_MALLOC_ERROR.
 **/
int
gsasl_init (Gsasl ** ctx)
{
  int i;

  if (gc_init () != GC_OK)
    return GSASL_CRYPTO_ERROR;

  *ctx = (Gsasl *) malloc (sizeof (**ctx));
  if (*ctx == NULL)
    return GSASL_MALLOC_ERROR;

  memset (*ctx, 0, sizeof (**ctx));

  i = 0;
  while (_gsasl_all_mechanisms[i].name)
    {
#ifdef USE_CLIENT
      if (_gsasl_all_mechanisms[i].client.init &&
	  _gsasl_all_mechanisms[i].client.init (*ctx) == GSASL_OK)
	{
	  if ((*ctx)->client_mechs)
	    (*ctx)->client_mechs = (_Gsasl_mechanism *)
	      realloc ((*ctx)->client_mechs,
		       sizeof (*(*ctx)->client_mechs) *
		       ((*ctx)->n_client_mechs + 1));
	  else
	    (*ctx)->client_mechs = (_Gsasl_mechanism *)
	      malloc (sizeof (*(*ctx)->client_mechs));

	  if ((*ctx)->client_mechs == NULL)
	    {
	      gsasl_done (*ctx);
	      return GSASL_MALLOC_ERROR;
	    }

	  (*ctx)->client_mechs[(*ctx)->n_client_mechs] =
	    _gsasl_all_mechanisms[i];
	  (*ctx)->n_client_mechs++;
	}
#endif

#ifdef USE_SERVER
      if (_gsasl_all_mechanisms[i].server.init &&
	  _gsasl_all_mechanisms[i].server.init (*ctx) == GSASL_OK)
	{
	  if ((*ctx)->server_mechs)
	    (*ctx)->server_mechs = (_Gsasl_mechanism *)
	      realloc ((*ctx)->server_mechs,
		       sizeof (*(*ctx)->server_mechs) *
		       ((*ctx)->n_server_mechs + 1));
	  else
	    (*ctx)->server_mechs = (_Gsasl_mechanism *)
	      malloc (sizeof (*(*ctx)->server_mechs));

	  if ((*ctx)->server_mechs == NULL)
	    {
	      gsasl_done (*ctx);
	      return GSASL_MALLOC_ERROR;
	    }

	  (*ctx)->server_mechs[(*ctx)->n_server_mechs] =
	    _gsasl_all_mechanisms[i];
	  (*ctx)->n_server_mechs++;
	}
#endif

      i++;
    }

  return GSASL_OK;
}
