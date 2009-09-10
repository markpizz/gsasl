/* parser.c --- SCRAM parser.
 * Copyright (C) 2009  Simon Josefsson
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
# include "config.h"
#endif

/* Get prototypes. */
#include "parser.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen, strchrnul. */
#include <string.h>

/* Get validator. */
#include "validate.h"

int
scram_parse_client_first (const char *str, size_t len,
			  struct scram_client_first *cf)
{
  /* Minimum client first string is 'n,,n=a,r=b'. */
  if (len < 10)
    return -1;

  if (*str != 'p' && *str != 'n' && *str != 'y')
    return -1;

  cf->cbflag = *str++;
  if (cf->cbflag == 'p')
    {
      /* FIXME parse cbname */
      return -1;
    }

  if (*str++ != ',')
    return -1;

  if (*str == 'a')
    {
      /* FIXME parse authzid */
      return -1;
    }

  if (*str++ != ',')
    return -1;

  if (*str++ != 'n')
    return -1;

  if (*str++ != '=')
    return -1;

  {
    char *p;
    size_t len;

    p = strchr (str, ',');
    if (!p)
      return -1;

    len = p - str;

    cf->username = malloc (len + 1);
    if (!cf->username)
      return -1;

    memcpy (cf->username, str, len);
    cf->username[len] = '\0';

    str = p;
  }

  if (*str++ != ',')
    return -1;

  if (*str++ != 'r')
    return -1;

  if (*str++ != '=')
    return -1;

  {
    char *p;
    size_t len;

    p = strchrnul (str, ',');
    if (!p)
      return -1;

    len = p - str;

    cf->username = malloc (len + 1);
    if (!cf->username)
      return -1;

    memcpy (cf->username, str, len);
    cf->username[len] = '\0';

    str = p;
  }

  return 0;
}
