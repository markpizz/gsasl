/* stringprep.c	internationalized SASL string processing
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

#include <stringprep.h>

char *
gsasl_stringprep_nfkc (const char *in, ssize_t len)
{
  char *out;

  out = gsasl_stringprep_nfkc (in, len);

  return out;
}

char *
gsasl_stringprep_saslprep (const char *in, int *stringprep_rc)
{
  char *out;
  int rc;

  rc = stringprep_profile (in, &out, "SASLprep", 0);
  if (stringprep_rc)
    *stringprep_rc = rc;
  if (!rc)
    out = NULL;

  return out;
}

char *
gsasl_stringprep_trace (const char *in, int *stringprep_rc)
{
  char *out;
  int rc;

  rc = stringprep_profile (in, &out, "trace", 0);
  if (stringprep_rc)
    *stringprep_rc = rc;
  if (!rc)
    out = NULL;

  return out;
}
