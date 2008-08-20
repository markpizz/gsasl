/* name.c --- Test the gsasl_mechanism_name function.
 * Copyright (C) 2008  Simon Josefsson
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

#include "utils.h"

void
doit (void)
{
  Gsasl *ctx = NULL;
  Gsasl_session *server = NULL, *client = NULL;
  int res;
  const char *p;

  p = gsasl_mechanism_name (NULL);
  if (p != NULL)
    fail ("gsasl_mechanism_name (NULL) failed: %s\n", p);
  success ("gsasl_mechanism_name (NULL) ok\n");

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  res = gsasl_server_start (ctx, "CRAM-MD5", &server);
  if (res != GSASL_OK)
    fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
  else
    {
      p = gsasl_mechanism_name (server);

      if (!p)
	fail ("gsasl_mechanism_name() returned NULL.\n");
      else if (strcmp ("CRAM-MD5", p) == 0)
	success ("gsasl_mechanism_name() returned correct %s\n", p);
      else
	fail ("gsasl_mechanism_name() returned incorrect %s", p);

      gsasl_finish (server);
    }

  res = gsasl_client_start (ctx, "PLAIN", &client);
  if (res != GSASL_OK)
    fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
  else
    {
      p = gsasl_mechanism_name (client);

      if (!p)
	fail ("gsasl_mechanism_name() returned NULL.\n");
      else if (strcmp ("PLAIN", p) == 0)
	success ("gsasl_mechanism_name() returned correct %s\n", p);
      else
	fail ("gsasl_mechanism_name() returned incorrect %s", p);

      gsasl_finish (client);
    }

  gsasl_done (ctx);
}
