/* init.c	entry point for libgsasl
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

#if ENABLE_NLS
char *
_gsasl_gettext (const char *str)
{
  return dgettext (PACKAGE, str);
}

static void
_gsasl_gettext_init (void)
{
  bindtextdomain (PACKAGE, LOCALEDIR);
#ifdef HAVE_BIND_TEXTDOMAIN_CODESET
  bind_textdomain_codeset (PACKAGE, "UTF-8");
#endif
  textdomain (PACKAGE);
}
#endif /* ENABLE_NLS */

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
gsasl_init (Gsasl_ctx ** ctx)
{
  int i;

#if ENABLE_NLS
  _gsasl_gettext_init ();
#endif

  *ctx = (Gsasl_ctx *) malloc (sizeof (**ctx));
  if (*ctx == NULL)
    return GSASL_MALLOC_ERROR;

  memset (*ctx, 0, sizeof (**ctx));

  i = 0;
  while (_gsasl_all_mechanisms[i].name)
    {
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

      i++;
    }

  return GSASL_OK;
}
