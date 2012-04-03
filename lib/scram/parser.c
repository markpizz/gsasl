/* parser.c --- SCRAM parser.
 * Copyright (C) 2009-2012 Simon Josefsson
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

/* Get prototypes. */
#include "parser.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

/* Get validator. */
#include "validate.h"

/* Get c_isalpha. */
#include "c-ctype.h"

static char *
unescape (const char *str, size_t len)
{
  char *out = malloc (len + 1);
  char *p = out;

  if (!out)
    return NULL;

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
      else
	{
	  *p++ = *str;
	  str++;
	  len--;
	}
    }
  *p = '\0';

  return out;
}

int
scram_parse_client_first (const char *str, size_t len,
			  struct scram_client_first *cf)
{
  /* Minimum client first string is 'n,,n=a,r=b'. */
  if (strnlen (str, len) < 10)
    return -1;

  if (len == 0 || (*str != 'n' && *str != 'y' && *str != 'p'))
    return -1;
  cf->cbflag = *str;
  str++, len--;

  if (cf->cbflag == 'p')
    {
      const char *p;

      if (len == 0 || *str != '=')
	return -1;
      str++, len--;

      p = memchr (str, ',', len);
      if (!p)
	return -1;
      cf->cbname = malloc (p - str + 1);
      if (!cf->cbname)
	return -1;
      memcpy (cf->cbname, str, p - str);
      cf->cbname[p - str] = '\0';
      len -= (p - str);
      str += (p - str);
    }

  if (len == 0 || *str != ',')
    return -1;
  str++, len--;

  if (len == 0)
    return -1;
  if (*str == 'a')
    {
      const char *p;
      size_t l;

      str++, len--;
      if (len == 0 || *str != '=')
	return -1;
      str++, len--;

      p = memchr (str, ',', len);
      if (!p)
	return -1;

      l = p - str;
      if (len < l)
	return -1;

      cf->authzid = unescape (str, l);
      if (!cf->authzid)
	return -1;

      str = p;
      len -= l;
    }

  if (len == 0 || *str != ',')
    return -1;
  str++, len--;

  if (len == 0 || *str != 'n')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  {
    const char *p;
    size_t l;

    p = memchr (str, ',', len);
    if (!p)
      return -1;

    l = p - str;
    if (len < l)
      return -1;

    cf->username = unescape (str, l);
    if (!cf->username)
      return -1;

    str = p;
    len -= l;
  }

  if (len == 0 || *str != ',')
    return -1;
  str++, len--;

  if (len == 0 || *str != 'r')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  {
    const char *p;
    size_t l;

    p = memchr (str, ',', len);
    if (!p)
      p = str + len;
    if (!p)
      return -1;

    l = p - str;
    if (len < l)
      return -1;

    cf->client_nonce = malloc (l + 1);
    if (!cf->client_nonce)
      return -1;

    memcpy (cf->client_nonce, str, l);
    cf->client_nonce[l] = '\0';

    str = p;
    len -= l;
  }

  /* FIXME check that any extension fields follow valid syntax. */

  if (scram_valid_client_first (cf) < 0)
    return -1;

  return 0;
}

int
scram_parse_server_first (const char *str, size_t len,
			  struct scram_server_first *sf)
{
  /* Minimum server first string is 'r=ab,s=biws,i=1'. */
  if (strnlen (str, len) < 15)
    return -1;

  if (len == 0 || *str != 'r')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  {
    const char *p;
    size_t l;

    p = memchr (str, ',', len);
    if (!p)
      return -1;

    l = p - str;
    if (len < l)
      return -1;

    sf->nonce = malloc (l + 1);
    if (!sf->nonce)
      return -1;

    memcpy (sf->nonce, str, l);
    sf->nonce[l] = '\0';

    str = p;
    len -= l;
  }

  if (len == 0 || *str != ',')
    return -1;
  str++, len--;

  if (len == 0 || *str != 's')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  {
    const char *p;
    size_t l;

    p = memchr (str, ',', len);
    if (!p)
      return -1;

    l = p - str;
    if (len < l)
      return -1;

    sf->salt = malloc (l + 1);
    if (!sf->salt)
      return -1;

    memcpy (sf->salt, str, l);
    sf->salt[l] = '\0';

    str = p;
    len -= l;
  }

  if (len == 0 || *str != ',')
    return -1;
  str++, len--;

  if (len == 0 || *str != 'i')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  sf->iter = 0;
  for (; len > 0 && *str >= '0' && *str <= '9'; str++, len--)
    {
      size_t last_iter = sf->iter;

      sf->iter = sf->iter * 10 + (*str - '0');

      /* Protect against wrap arounds. */
      if (sf->iter < last_iter)
	return -1;
    }

  if (len > 0 && *str != ',')
    return -1;

  /* FIXME check that any extension fields follow valid syntax. */

  if (scram_valid_server_first (sf) < 0)
    return -1;

  return 0;
}

int
scram_parse_client_final (const char *str, size_t len,
			  struct scram_client_final *cl)
{
  /* Minimum client final string is 'c=biws,r=ab,p=ab=='. */
  if (strnlen (str, len) < 18)
    return -1;

  if (len == 0 || *str != 'c')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  {
    const char *p;
    size_t l;

    p = memchr (str, ',', len);
    if (!p)
      return -1;

    l = p - str;
    if (len < l)
      return -1;

    cl->cbind = malloc (l + 1);
    if (!cl->cbind)
      return -1;

    memcpy (cl->cbind, str, l);
    cl->cbind[l] = '\0';

    str = p;
    len -= l;
  }

  if (len == 0 || *str != ',')
    return -1;
  str++, len--;

  if (len == 0 || *str != 'r')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  {
    const char *p;
    size_t l;

    p = memchr (str, ',', len);
    if (!p)
      return -1;

    l = p - str;
    if (len < l)
      return -1;

    cl->nonce = malloc (l + 1);
    if (!cl->nonce)
      return -1;

    memcpy (cl->nonce, str, l);
    cl->nonce[l] = '\0';

    str = p;
    len -= l;
  }

  if (len == 0 || *str != ',')
    return -1;
  str++, len--;

  /* Ignore extensions. */
  while (len > 0 && c_isalpha (*str) && *str != 'p')
    {
      const char *p;
      size_t l;

      str++, len--;

      if (len == 0 || *str != '=')
	return -1;
      str++, len--;

      p = memchr (str, ',', len);
      if (!p)
	return -1;
      p++;

      l = p - str;
      if (len < l)
	return -1;

      str = p;
      len -= l;
    }

  if (len == 0 || *str != 'p')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  /* Sanity check proof. */
  if (memchr (str, '\0', len))
    return -1;

  cl->proof = malloc (len + 1);
  if (!cl->proof)
    return -1;

  memcpy (cl->proof, str, len);
  cl->proof[len] = '\0';

  if (scram_valid_client_final (cl) < 0)
    return -1;

  return 0;
}

int
scram_parse_server_final (const char *str, size_t len,
			  struct scram_server_final *sl)
{
  /* Minimum client final string is 'v=ab=='. */
  if (strnlen (str, len) < 6)
    return -1;

  if (len == 0 || *str != 'v')
    return -1;
  str++, len--;

  if (len == 0 || *str != '=')
    return -1;
  str++, len--;

  /* Sanity check proof. */
  if (memchr (str, '\0', len))
    return -1;

  sl->verifier = malloc (len + 1);
  if (!sl->verifier)
    return -1;

  memcpy (sl->verifier, str, len);
  sl->verifier[len] = '\0';

  if (scram_valid_server_final (sl) < 0)
    return -1;

  return 0;
}
