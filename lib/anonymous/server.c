/* server.c --- ANONYMOUS mechanism as defined in RFC 2245, server side.
 * Copyright (C) 2002, 2003, 2004, 2005  Simon Josefsson
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "anonymous.h"

int
_gsasl_anonymous_server_step (Gsasl_session * sctx,
			      void *mech_data,
			      const char *input, size_t input_len,
			      char **output, size_t * output_len)
{
  *output = NULL;
  *output_len = 0;

  /* token       = 1*255TCHAR */
  if (input_len == 0)
    return GSASL_NEEDS_MORE;

  /* FIXME: Validate that input is UTF-8. */

  gsasl_property_set_raw (sctx, GSASL_ANONYMOUS_TOKEN, input, input_len);

  return gsasl_callback (NULL, sctx, GSASL_VALIDATE_ANONYMOUS);
}
