/* stringprep-no.c --- Dummy i18n SASL string processing functions.
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

/*
 * Note: this file is only used when --without-stringprep is specified.
 * Refer to stringprep.c for documentation.
 */

#include "internal.h"

char *
gsasl_stringprep_nfkc (const char *in, ssize_t len)
{
  char *out;

  if (len >= 0)
    {
      out = malloc (len + 1);
      if (out)
	{
	  memcpy (out, in, len);
	  out[len] = '\0';
	}
    }
  else
    out = NULL;

  return out;
}

static char *
no_stringprep (const char *in, int *stringprep_rc)
{
  char *out;
  int rc;

  out = malloc (strlen (in) + 1);
  if (out)
    {
      strcpy (out, in);
      if (stringprep_rc)
	*stringprep_rc = 1;
    }
  else if (stringprep_rc)
    *stringprep_rc = 0;

  return out;
}

char *
gsasl_stringprep_saslprep (const char *in, int *stringprep_rc)
{
  return no_stringprep (in, stringprep_rc);
}

char *
gsasl_stringprep_trace (const char *in, int *stringprep_rc)
{
  return no_stringprep (in, stringprep_rc);
}
