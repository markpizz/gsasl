/* printer.h --- Convert SCRAM token structures into strings.
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
#include "printer.h"

/* Get free. */
#include <stdlib.h>

/* Get asprintf. */
#include <stdio.h>

/* Get strdup. */
#include <string.h>

/* Get token validator. */
#include "validate.h"

static char *
scram_escape (const char *str)
{
  /* FIXME escape '=' and ',' in authzid to '=3D' and '=2C'
     respectively. */
  return strdup (str);
}

/* Print SCRAM client-first token into newly allocated output string
   OUT.  Returns 0 on success, -1 on invalid token, and -2 on memory
   allocation errors. */
int
scram_print_client_first (struct scram_client_first *cf, char **out)
{
  char *username = NULL;
  char *authzid = NULL;
  int n;

  /* Below we assume fields are sensible, so first verify that to
     avoid crashes. */
  if (!scram_valid_client_first (cf))
    return -1;

  /* Escape username and authzid. */

  username = scram_escape (cf->username);
  if (!username)
    return -2;

  if (cf->authzid)
    {
      authzid = scram_escape (cf->authzid);
      if (!authzid)
	return -2;
    }

  n = asprintf (out, "%c%s%s,%s%s,n=%s,r=%s",
		cf->cbflag,
		cf->cbflag == 'p' ? "=" : "",
		cf->cbflag == 'p' ? cf->cbname : "",
		authzid ? "a=" : "",
		authzid ? authzid : "",
		username,
		cf->client_nonce);

  free (username);
  free (authzid);

  if (n <= 0 || *out == NULL)
    return -1;

  return 0;
}

/* Print SCRAM server-first token into newly allocated output string
   OUT.  Returns 0 on success, -1 on invalid token, and -2 on memory
   allocation errors. */
int
scram_print_server_first (struct scram_server_first *sf, char **out)
{
  int n;

  /* Below we assume fields are sensible, so first verify that to
     avoid crashes. */
  if (!scram_valid_server_first (sf))
    return -1;

  n = asprintf (out, "r=%s,s=%s,i=%d",
		sf->nonce, sf->salt, sf->iter);
  if (n <= 0 || *out == NULL)
    return -1;

  return 0;
}

/* Print SCRAM client-final token into newly allocated output string
   OUT.  Returns 0 on success, -1 on invalid token, and -2 on memory
   allocation errors. */
int
scram_print_client_final (struct scram_client_final *cl, char **out)
{
  int n;

  /* Below we assume fields are sensible, so first verify that to
     avoid crashes. */
  if (!scram_valid_client_final (cl))
    return -1;

  n = asprintf (out, "c=%s,r=%s,p=%s",
		cl->cbind, cl->nonce, cl->proof);
  if (n <= 0 || *out == NULL)
    return -1;

  return 0;
}

/* Print SCRAM server-final token into newly allocated output string
   OUT.  Returns 0 on success, -1 on invalid token, and -2 on memory
   allocation errors. */
int
scram_print_server_final (struct scram_server_final *sl, char **out)
{
  int n;

  /* Below we assume fields are sensible, so first verify that to
     avoid crashes. */
  if (!scram_valid_server_final (sl))
    return -1;

  n = asprintf (out, "v=%s", sl->verifier);
  if (n <= 0 || *out == NULL)
    return -1;

  return 0;
}
