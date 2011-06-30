/* saml20.c --- Test the SAML20 mechanism.
 * Copyright (C) 2010, 2011  Simon Josefsson
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

const char *samlchallenge =
  "https://saml.example.org/SAML/Browser?SAMLRequest=PHNhbWxwOk"
  "F1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOl"
  "NBTUw6Mi4wOnByb3RvY29sIg0KICAgIElEPSJfYmVjNDI0ZmE1MTAzNDI4OT"
  "A5YTMwZmYxZTMxMTY4MzI3Zjc5NDc0OTg0IiBWZXJzaW9uPSIyLjAiDQogIC"
  "AgSXNzdWVJbnN0YW50PSIyMDA3LTEyLTEwVDExOjM5OjM0WiIgRm9yY2VBdX"
  "Robj0iZmFsc2UiDQogICAgSXNQYXNzaXZlPSJmYWxzZSINCiAgICBQcm90b2"
  "NvbEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpiaW5kaW"
  "5nczpIVFRQLVBPU1QiDQogICAgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVV"
  "JMPQ0KICAgICAgICAiaHR0cHM6Ly94bXBwLmV4YW1wbGUuY29tL1NBTUwvQX"
  "NzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlIj4NCiA8c2FtbDpJc3N1ZXIgeG1sbn"
  "M6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbi"
  "I+DQogICAgIGh0dHBzOi8veG1wcC5leGFtcGxlLmNvbQ0KIDwvc2FtbDpJc3"
  "N1ZXI+DQogPHNhbWxwOk5hbWVJRFBvbGljeSB4bWxuczpzYW1scD0idXJuOm"
  "9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIg0KICAgICBGb3JtYX"
  "Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0On"
  "BlcnNpc3RlbnQiDQogICAgIFNQTmFtZVF1YWxpZmllcj0ieG1wcC5leGFtcG"
  "xlLmNvbSIgQWxsb3dDcmVhdGU9InRydWUiIC8+DQogPHNhbWxwOlJlcXVlc3"
  "RlZEF1dGhuQ29udGV4dA0KICAgICB4bWxuczpzYW1scD0idXJuOm9hc2lzOm"
  "5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiANCiAgICAgICAgQ29tcGFyaX"
  "Nvbj0iZXhhY3QiPg0KICA8c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZg0KIC"
  "AgICAgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm"
  "Fzc2VydGlvbiI+DQogICAgICAgICAgIHVybjpvYXNpczpuYW1lczp0YzpTQU"
  "1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0DQ"
  "ogIDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj4NCiA8L3NhbWxwOlJlcX"
  "Vlc3RlZEF1dGhuQ29udGV4dD4gDQo8L3NhbWxwOkF1dGhuUmVxdWVzdD4=";

static int
client_callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  /* The first round, the mechanism will need an authorization name
     and a SAML IDP.  The next round it will request that the client
     redirects the user (in the browser) using the data stored in the
     GSASL_SAML20_REDIRECT_URL property.  */

  switch (prop)
    {
    case GSASL_AUTHZID:
      rc = GSASL_OK;
      break;

    case GSASL_SAML20_IDP_IDENTIFIER:
      gsasl_property_set (sctx, prop, "https://saml.example.org/");
      rc = GSASL_OK;
      break;

    case GSASL_SAML20_AUTHENTICATE_IN_BROWSER:
      printf ("client got redirect URL: %s\n",
	      gsasl_property_get (sctx, GSASL_SAML20_REDIRECT_URL));
      rc = GSASL_OK;
      break;

    default:
      fail ("Unknown client callback property %d\n", prop);
      break;
    }

  return rc;
}

static int
server_callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  /* The first round the mechanism will want the SAML challenge to
     send to the client.  The next round it wants an authorization
     decision. */

  switch (prop)
    {
    case GSASL_SAML20_REDIRECT_URL:
      printf ("server got identity: %s\n",
	      gsasl_property_get (sctx, GSASL_SAML20_IDP_IDENTIFIER));
      gsasl_property_set (sctx, prop, samlchallenge);
      rc = GSASL_OK;
      break;

    case GSASL_VALIDATE_SAML20:
      printf ("server authenticating user OK\n");
      rc = GSASL_OK;
      break;

    default:
      fail ("Unknown server callback property %d\n", prop);
      break;
    }

  return rc;
}

void
doit (void)
{
  Gsasl *c = NULL, *s = NULL;
  Gsasl_session *server = NULL, *client = NULL;
  char *s1, *s2;
  int res;

  res = gsasl_init (&c);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  res = gsasl_init (&s);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (!gsasl_client_support_p (c, "SAML20"))
    {
      gsasl_done (c);
      fail("No support for SAML20 clients.\n");
      exit(77);
    }

  if (!gsasl_server_support_p (s, "SAML20"))
    {
      gsasl_done (s);
      fail("No support for SAML20 servers.\n");
      exit(77);
    }

  gsasl_callback_set (c, client_callback);
  gsasl_callback_set (s, server_callback);

  /* Simple client */

  res = gsasl_client_start (c, "SAML20", &client);
  if (res != GSASL_OK)
    {
      fail ("gsasl_client_start (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  res = gsasl_server_start (s, "SAML20", &server);
  if (res != GSASL_OK)
    {
      fail ("gsasl_server_start (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  res = gsasl_step64 (client, NULL, &s1);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step client1 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: `%s' (%d)\n", s1 ? s1 : "", (int) strlen (s1));

  res = gsasl_step64 (server, s1, &s2);
  gsasl_free (s1);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step server1 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("S: `%s' (%d)\n", s2 ? s2 : "", (int) strlen (s2));

  res = gsasl_step64 (client, s2, &s1);
  gsasl_free (s2);
  if (res != GSASL_OK)
    {
      fail ("gsasl_step client2 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: `%s' (%d)\n", s1 ? s1 : "", (int) strlen (s1));

  res = gsasl_step64 (server, s1, &s2);
  gsasl_free (s1);
  if (res != GSASL_OK)
    {
      fail ("gsasl_step server2 (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("S: `%s' (%d)\n", s2 ? s2 : "", (int) strlen (s2));

  gsasl_free (s2);

  gsasl_finish (client);
  gsasl_finish (server);

  gsasl_done (c);
  gsasl_done (s);
}
