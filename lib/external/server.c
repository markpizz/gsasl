/* server.c --- EXTERNAL mechanism as defined in RFC 2222, server side.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#include "external.h"

int
_gsasl_external_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  return GSASL_OK;
}

int
_gsasl_external_server_step (Gsasl_session_ctx * sctx,
			     void *mech_data,
			     const char *input, size_t input_len,
			     char **output, size_t * output_len)
{
  *output_len = 0;
  *output = NULL;

  if (input_len > 0)
    {
      char *p;

      p = malloc (input_len + 1);
      if (!p)
	return GSASL_MALLOC_ERROR;
      memcpy (p, input, input_len);
      p[input_len] = '\0';

      /* An authorization identity is a string of zero or more Unicode
	 [Unicode] coded characters.  The NUL <U+0000> character is not
	 permitted in authorization identities. */
      if (input_len != strlen (p))
	return GSASL_MECHANISM_PARSE_ERROR;

      gsasl_property_set (sctx, GSASL_AUTHZID, p);

      free (p);
    }

  return gsasl_callback (sctx, GSASL_SERVER_EXTERNAL);
}
