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
scram_parse_client_first (const char *str,
			  struct scram_client_first *cf)
{
  /* Minimum client first string is 'n,,n=a,r=b'. */
  if (strlen (str) < 10)
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

    cf->client_nonce = malloc (len + 1);
    if (!cf->client_nonce)
      return -1;

    memcpy (cf->client_nonce, str, len);
    cf->client_nonce[len] = '\0';

    str = p;
  }

  /* FIXME check that any extension fields follow valid syntax. */

  if (scram_valid_client_first (cf) < 0)
    return -1;

  return 0;
}

int
scram_parse_server_first (const char *str,
			  struct scram_server_first *sf)
{
  /* Minimum server first string is 'r=ab,s=biws,i=1'. */
  if (strlen (str) < 15)
    return -1;

  if (*str++ != 'r')
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

    sf->nonce = malloc (len + 1);
    if (!sf->nonce)
      return -1;

    memcpy (sf->nonce, str, len);
    sf->nonce[len] = '\0';

    str = p;
  }

  if (*str++ != ',')
    return -1;

  if (*str++ != 's')
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

    sf->salt = malloc (len + 1);
    if (!sf->salt)
      return -1;

    memcpy (sf->salt, str, len);
    sf->salt[len] = '\0';

    /* FIXME check that salt is valid base64. */

    str = p;
  }

  if (*str++ != ',')
    return -1;

  if (*str++ != 'i')
    return -1;

  if (*str++ != '=')
    return -1;

  {
    const char *p;

    sf->iter = 0;
    for (p = str; *p >= '0' && *p <= '9'; p++)
      {
	size_t last_iter = sf->iter;

	sf->iter = sf->iter * 10 + (*p - '0');

	/* Protect against wrap arounds. */
	if (sf->iter < last_iter)
	  return -1;
      }

    if (*p != ',' && *p != '\0')
      return -1;

    str = p;
  }

  /* FIXME check that any extension fields follow valid syntax. */

  if (scram_valid_server_first (sf) < 0)
    return -1;

  return 0;
}
