/* saslprep.c --- Internationalized SASL string processing.
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

#include <stringprep.h>

/**
 * gsasl_saslprep - prepare internationalized string
 * @in: a UTF-8 encoded string.
 * @flags: any SASLprep flag, e.g., %GSASL_ALLOW_UNASSIGNED.
 * @out: on exit, contains newly allocated output string.
 * @stringpreprc: if non-NULL, will hold precise stringprep return code.
 *
 * Prepare string using SASLprep.  On success, the @out variable must
 * be deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK on success, or
 * %GSASL_SASLPREP_ERROR on error.
 *
 * Since: 0.2.3
 **/
int
gsasl_saslprep (const char *in, Gsasl_saslprep_flags flags,
		char **out, int *stringpreprc)
{
  int rc;

  rc = stringprep_profile (in, out, "SASLprep",
			   (flags & GSASL_ALLOW_UNASSIGNED)
			   ? STRINGPREP_NO_UNASSIGNED : 0);

  if (stringpreprc)
    *stringpreprc = rc;

  if (rc != STRINGPREP_OK)
    {
      *out = NULL;
      return GSASL_SASLPREP_ERROR;
    }

  return GSASL_OK;
}
