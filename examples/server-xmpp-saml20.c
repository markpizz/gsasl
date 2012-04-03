/* server-xmpp-saml20.c --- Example XMPP SASL SAML20 server.
 * Copyright (C) 2004-2012  Simon Josefsson
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gsasl.h>

static char *
xmltob64 (char *buf)
{
  while (*buf && *buf != '>')
    buf++;
  if (*buf)
    buf++;
  while (*buf && buf[strlen (buf) - 1] != '<')
    buf[strlen (buf) - 1] = '\0';
  if (*buf)
    buf[strlen (buf) - 1] = '\0';
  return buf;
}

static void
server_xmpp (Gsasl_session * session)
{
  char *b64, *p;
  int rc = GSASL_AUTHENTICATION_ERROR;

  do
    {
      char buf[BUFSIZ] = "";

      p = fgets (buf, sizeof (buf) - 1, stdin);
      if (p == NULL)
	{
	  perror ("fgets");
	  break;
	}
      if (buf[strlen (buf) - 1] == '\n')
        buf[strlen (buf) - 1] = '\0';

      b64 = xmltob64 (buf);

      printf ("parsed: '%s'\n", b64);

      rc = gsasl_step64 (session, b64, &p);
      if (rc == GSASL_NEEDS_MORE)
	{
	  printf ("<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
		  "%s</challenge>\n", p);
	  gsasl_free (p);
	}
    }
  while (rc == GSASL_NEEDS_MORE);

  if (rc == GSASL_OK)
    puts ("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
  else
    {
      puts ("<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
	    "<temporary-auth-failure/></failure></stream:stream>");
      printf ("Authentication error (%d): %s\n", rc, gsasl_strerror (rc));
    }
}

static void
server (Gsasl * ctx)
{
  Gsasl_session *session;
  const char *mech = "SAML20";
  int rc;

  /* Create new authentication session. */
  if ((rc = gsasl_server_start (ctx, mech, &session)) != GSASL_OK)
    {
      printf ("Cannot initialize client (%d): %s\n", rc, gsasl_strerror (rc));
      return;
    }

  /* Do it. */
  server_xmpp (session);

  /* Cleanup. */
  gsasl_finish (session);
}

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
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  /* Get user info from user. */

  switch (prop)
    {
    case GSASL_REDIRECT_URL:
      printf ("server got identity: %s\n",
	      gsasl_property_get (sctx, GSASL_SAML20_IDP_IDENTIFIER));
      gsasl_property_set (sctx, prop, samlchallenge);
      rc = GSASL_OK;
      break;

    case GSASL_VALIDATE_SAML20:
      {
	char buf[BUFSIZ] = "";
	char *p;

	puts ("Authorization decision time!");
	printf ("User identity: %s\n",
		gsasl_property_get (sctx, GSASL_SAML20_IDP_IDENTIFIER));
	printf ("Accept user? (y/n) ");
	fflush (stdout);

	p = fgets (buf, sizeof (buf) - 1, stdin);
	if (p == NULL)
	  {
	    perror ("fgets");
	    break;
	  }
	if (buf[strlen (buf) - 1] == '\n')
	  buf[strlen (buf) - 1] = '\0';

	if (strcmp (buf, "y") == 0 || strcmp (buf, "Y") == 0)
	  rc = GSASL_OK;
	else
	  rc = GSASL_AUTHENTICATION_ERROR;
      }
      break;

    default:
      printf ("Unknown property %d!  Don't worry.\n", prop);
      break;
    }

  return rc;
}

int
main (int argc, char *argv[])
{
  Gsasl *ctx = NULL;
  int rc;

  /* Initialize library. */
  if ((rc = gsasl_init (&ctx)) != GSASL_OK)
    {
      printf ("Cannot initialize libgsasl (%d): %s", rc, gsasl_strerror (rc));
      return 1;
    }

  /* Set the callback handler for the library. */
  gsasl_callback_set (ctx, callback);

  /* Do it. */
  server (ctx);

  /* Cleanup. */
  gsasl_done (ctx);

  return 0;
}
