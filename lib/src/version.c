/* version.c -- Version handling.
 * Copyright (C) 2002, 2004  Simon Josefsson
 * Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
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

/* This file is based on src/global.c in libgcrypt */

#include "internal.h"

/* Get isdigit. */
# include <ctype.h>

static const char *
_gsasl_parse_version_number (const char *s, int *number)
{
  int val = 0;

  if (*s == '0' && isdigit (s[1]))
    return NULL;		/* leading zeros are not allowed */
  for (; isdigit (*s); s++)
    {
      val *= 10;
      val += *s - '0';
    }
  *number = val;
  return val < 0 ? NULL : s;
}


static const char *
_gsasl_parse_version_string (const char *s, int *major, int *minor,
			     int *micro)
{
  s = _gsasl_parse_version_number (s, major);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = _gsasl_parse_version_number (s, minor);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = _gsasl_parse_version_number (s, micro);
  if (!s)
    return NULL;
  return s;			/* patchlevel */
}

/**
 * gsasl_check_version:
 * @req_version: version string to compare with, or NULL
 *
 * Check library version.
 *
 * Return value: Check that the the version of the library is at
 *   minimum the one given as a string in @req_version and return the
 *   actual version string of the library; return NULL if the
 *   condition is not met.  If %NULL is passed to this function no
 *   check is done and only the version string is returned.
 **/
const char *
gsasl_check_version (const char *req_version)
{
  const char *ver = VERSION;
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_plvl, *rq_plvl;

  if (!req_version)
    return ver;

  my_plvl = _gsasl_parse_version_string (ver,
					 &my_major, &my_minor, &my_micro);
  if (!my_plvl)
    return NULL;		/* very strange our own version is bogus */
  rq_plvl = _gsasl_parse_version_string (req_version, &rq_major, &rq_minor,
					 &rq_micro);
  if (!rq_plvl)
    return NULL;		/* req version string is invalid */

  if (my_major > rq_major
      || (my_major == rq_major && my_minor > rq_minor)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro > rq_micro)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro == rq_micro && strcmp (my_plvl, rq_plvl) >= 0))
    {
      return ver;
    }
  return NULL;
}
