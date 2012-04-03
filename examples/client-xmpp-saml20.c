/* client-xmpp-saml20.c --- Example XMPP SASL SAML20 client.
 * Copyright (C) 2004, 2005, 2007, 2009, 2010, 2012  Simon Josefsson
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
client_xmpp (Gsasl_session * session)
{
  char buf[BUFSIZ] = "";
  char *p;
  int rc;

  /* This loop mimics a protocol where the client send data first,
     which is something that XMPP supports.  For simplicity, it
     requires that server send the XML blob on one line and XML parser
     is not complete.  */

  /* Generate client output. */
  rc = gsasl_step64 (session, buf, &p);
  if (rc != GSASL_NEEDS_MORE)
    {
      printf ("SAML20 step error (%d): %s\n", rc, gsasl_strerror (rc));
      return;
    }

  printf ("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "
	  "mechanism='SAML20'>%s</auth>\n", p);

  do
    {
      char *b64;

      fgets (buf, sizeof (buf) - 1, stdin);
      if (buf[strlen (buf) - 1] == '\n')
        buf[strlen (buf) - 1] = '\0';

      b64 = xmltob64 (buf);

      printf ("parsed: '%s'\n", b64);

      rc = gsasl_step64 (session, b64, &p);
      if (rc != GSASL_NEEDS_MORE && rc != GSASL_OK)
	{
	  printf ("SAML20 step error (%d): %s\n", rc, gsasl_strerror (rc));
	  return;
	}

      printf ("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
	      "%s</response>\n", p);

    }
  while (rc == GSASL_NEEDS_MORE);

  if (rc != GSASL_OK)
    {
      printf ("Authentication error (%d): %s\n", rc, gsasl_strerror (rc));
      return;
    }

  /* The client is done.  Here you would typically check if the server
     let the client in.  If not, you could try again. */

  printf ("If server accepted us, we're done.\n");
}

static void
client (Gsasl * ctx)
{
  Gsasl_session *session;
  const char *mech = "SAML20";
  int rc;

  /* Create new authentication session. */
  if ((rc = gsasl_client_start (ctx, mech, &session)) != GSASL_OK)
    {
      printf ("Cannot initialize client (%d): %s\n", rc, gsasl_strerror (rc));
      return;
    }

  /* Do it. */
  client_xmpp (session);

  /* Cleanup. */
  gsasl_finish (session);
}

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  /* Get user info from user. */

  switch (prop)
    {
    case GSASL_SAML20_IDP_IDENTIFIER:
      gsasl_property_set (sctx, prop, "https://saml.example.org/");
      rc = GSASL_OK;
      break;

    case GSASL_AUTHENTICATE_IN_BROWSER:
      printf ("client got redirect URL: %s\n",
	      gsasl_property_get (sctx, GSASL_REDIRECT_URL));
      rc = GSASL_OK;
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
  client (ctx);

  /* Cleanup. */
  gsasl_done (ctx);

  return 0;
}
