/* readnz.c --- Check out-of-bounds reads on non-zero terminated strings.
 * Copyright (C) 2010  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "utils.h"

static void
doit2 (bool server_p)
{
  Gsasl *ctx = NULL;
  Gsasl_session *session = NULL;
  char *mechs;
  char *mech, *ptrptr = NULL;
  char *s1;
  size_t s1len;
  int res;
  size_t i;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (server_p)
    res = gsasl_server_mechlist (ctx, &mechs);
  else
    res = gsasl_client_mechlist (ctx, &mechs);
  if (res != GSASL_OK)
    {
      fail ("mechlist() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  for (i = 0; (mech = strtok_r (i == 0 ? mechs : NULL, " ", &ptrptr)); i++)
    {
      size_t len;

      for (len = 0; len < 5; len++)
	{
	  char *p;

	  if (server_p)
	    res = gsasl_server_start (ctx, mech, &session);
	  else
	    res = gsasl_client_start (ctx, mech, &session);
	  if (res != GSASL_OK)
	    {
	      fail ("start(%s) failed (%d):\n%s\n", mech,
		    res, gsasl_strerror (res));
	      return;
	    }

	  p = malloc (len);
	  if (!p)
	    {
	      fail ("out of memory");
	      return;
	    }

	  memset (p, 42, len);

	  res = gsasl_step (session, p, len, &s1, &s1len);
	  if (res == GSASL_OK || res == GSASL_NEEDS_MORE)
	    gsasl_free (s1);

	  gsasl_free (p);

	  gsasl_finish (session);
	}
    }

  gsasl_free (mechs);

  gsasl_done (ctx);
}

void
doit (void)
{
  doit2 (true);
  doit2 (false);
}
