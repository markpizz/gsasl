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
  size_t i;
  int rc;

  if (gc_init () != GC_OK)
    return GSASL_CRYPTO_ERROR;

  *ctx = (Gsasl *) calloc (1, sizeof (**ctx));
  if (*ctx == NULL)
    return GSASL_MALLOC_ERROR;

  for (i = 0; _gsasl_all_mechanisms[i].name; i++)
    {
      rc = gsasl_register (*ctx, &_gsasl_all_mechanisms[i]);
      if (rc != GSASL_OK)
	{
	  gsasl_done (*ctx);
	  return rc;
	}
    }

  return GSASL_OK;
}
