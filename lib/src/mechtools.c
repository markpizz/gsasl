/* mechtools.c --- Helper functions available for use by any mechanism.
 * Copyright (C) 2010-2012 Simon Josefsson
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Get specification. */
#include "mechtools.h"

/* Get strcmp. */
#include <string.h>

/* Get malloc, free. */
#include <stdlib.h>

/* Get asprintf. */
#include <stdio.h>

/* Get error codes. */
#include <gsasl.h>

/* Create in AUTHZID a newly allocated copy of STR where =2C is
   replaced with , and =3D is replaced with =.  Return GSASL_OK on
   success, GSASL_MALLOC_ERROR on memory errors, GSASL_PARSE_ERRORS if
   string contains any unencoded ',' or incorrectly encoded
   sequence.  */
static int
unescape_authzid (const char *str, size_t len, char **authzid)
{
  char *p;

  if (memchr (str, ',', len) != NULL)
    return GSASL_MECHANISM_PARSE_ERROR;

  p = *authzid = malloc (len + 1);
  if (!p)
    return GSASL_MALLOC_ERROR;

  while (len > 0 && *str)
    {
      if (len >= 3 && str[0] == '=' && str[1] == '2' && str[2] == 'C')
	{
	  *p++ = ',';
	  str += 3;
	  len -= 3;
	}
      else if (len >= 3 && str[0] == '=' && str[1] == '3' && str[2] == 'D')
	{
	  *p++ = '=';
	  str += 3;
	  len -= 3;
	}
      else if (str[0] == '=')
	{
	  free (*authzid);
	  *authzid = NULL;
	  return GSASL_MECHANISM_PARSE_ERROR;
	}
      else
	{
	  *p++ = *str;
	  str++;
	  len--;
	}
    }
  *p = '\0';

  return GSASL_OK;
}

/* Parse the GS2 header containing flags and authorization identity.
   Put authorization identity (or NULL) in AUTHZID and length of
   header in HEADERLEN.  Return GSASL_OK on success or an error
   code.*/
int
_gsasl_parse_gs2_header (const char *data, size_t len,
			 char **authzid, size_t * headerlen)
{
  char *authzid_endptr;

  if (len < 3)
    return GSASL_MECHANISM_PARSE_ERROR;

  if (strncmp (data, "n,,", 3) == 0)
    {
      *headerlen = 3;
      *authzid = NULL;
    }
  else if (strncmp (data, "n,a=", 4) == 0 &&
	   (authzid_endptr = memchr (data + 4, ',', len - 4)))
    {
      int res;

      if (authzid_endptr == NULL)
	return GSASL_MECHANISM_PARSE_ERROR;

      res = unescape_authzid (data + 4, authzid_endptr - (data + 4), authzid);
      if (res != GSASL_OK)
	return res;

      *headerlen = authzid_endptr - data + 1;
    }
  else
    return GSASL_MECHANISM_PARSE_ERROR;

  return GSASL_OK;
}

/* Return newly allocated copy of STR with all occurrences of ','
   replaced with =2C and '=' with '=3D', or return NULL on memory
   allocation errors.  */
static char *
escape_authzid (const char *str)
{
  char *out = malloc (strlen (str) * 3 + 1);
  char *p = out;

  if (!out)
    return NULL;

  while (*str)
    {
      if (*str == ',')
	{
	  memcpy (p, "=2C", 3);
	  p += 3;
	}
      else if (*str == '=')
	{
	  memcpy (p, "=3D", 3);
	  p += 3;
	}
      else
	{
	  *p = *str;
	  p++;
	}
      str++;
    }
  *p = '\0';

  return out;
}

/* Generate a newly allocated GS2 header, escaping authzid
   appropriately, and appending EXTRA. */
int
_gsasl_gs2_generate_header (bool nonstd, char cbflag,
			    const char *cbname, const char *authzid,
			    size_t extralen, const char *extra,
			    char **gs2h, size_t * gs2hlen)
{
  int elen = extralen;
  char *gs2cbflag;
  int len;

  if (cbflag == 'p')
    len = asprintf (&gs2cbflag, "p=%s", cbname);
  else if (cbflag == 'n')
    len = asprintf (&gs2cbflag, "n");
  else if (cbflag == 'y')
    len = asprintf (&gs2cbflag, "y");
  else
    /* internal caller error */
    return GSASL_MECHANISM_PARSE_ERROR;

  if (len <= 0 || gs2cbflag == NULL)
    return GSASL_MALLOC_ERROR;

  if (authzid)
    {
      char *escaped_authzid = escape_authzid (authzid);

      if (!escaped_authzid)
	{
	  free (gs2cbflag);
	  return GSASL_MALLOC_ERROR;
	}

      len = asprintf (gs2h, "%s%s,a=%s,%.*s", nonstd ? "F," : "",
		      gs2cbflag, escaped_authzid, elen, extra);

      free (escaped_authzid);
    }
  else
    len = asprintf (gs2h, "%s%s,,%.*s", nonstd ? "F," : "", gs2cbflag,
		    elen, extra);

  free (gs2cbflag);

  if (len <= 0 || gs2h == NULL)
    return GSASL_MALLOC_ERROR;

  *gs2hlen = len;

  return GSASL_OK;
}
