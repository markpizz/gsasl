/* callbacks.c --- Implementation of gsasl callbacks.
 * Copyright (C) 2002-2012 Simon Josefsson
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

#include "internal.h"
#include "callbacks.h"

#include "striconv.h"
#include "readline.h"

#if HAVE_LANGINFO_CODESET
# include <langinfo.h>		/* For nl_langinfo. */
#endif

static char *
locale_to_utf8 (char *str)
{
#if HAVE_LANGINFO_CODESET
  if (str)
    {
      char *from = nl_langinfo (CODESET);
      char *q = str_iconv (str, from, "UTF-8");
      if (!q)
	fprintf (stderr, "warning: Could not convert string to UTF-8...\n");
      else
	{
	  free (str);
	  str = q;
	}
    }
#endif

  return str;
}

static char *
readutf8line (const char *prompt)
{
  char *p = readline (prompt);

  return locale_to_utf8 (p);
}

static char *
readutf8pass (const char *prompt)
{
  char *p = getpass (prompt);

  return locale_to_utf8 (p);
}

int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  switch (prop)
    {
    case GSASL_ANONYMOUS_TOKEN:
      if (args_info.anonymous_token_arg == NULL)
	args_info.anonymous_token_arg =
	  readutf8line ("Enter anonymous token (e.g., email address): ");

      gsasl_property_set (sctx, GSASL_ANONYMOUS_TOKEN,
			  args_info.anonymous_token_arg);

      rc = GSASL_OK;
      break;

    case GSASL_CB_TLS_UNIQUE:
      if (!args_info.no_cb_flag && b64cbtlsunique == NULL
	  && args_info.hostname_arg == NULL)
	b64cbtlsunique =
	  readutf8line ("Enter base64 encoded tls-unique channel binding: ");
      if (!args_info.no_cb_flag && b64cbtlsunique && *b64cbtlsunique)
	gsasl_property_set (sctx, prop, b64cbtlsunique);
      rc = GSASL_OK;
      break;

    case GSASL_PASSWORD:
      if (args_info.password_arg == NULL)
	args_info.password_arg = readutf8pass ("Enter password: ");

      gsasl_property_set (sctx, GSASL_PASSWORD, args_info.password_arg);

      rc = GSASL_OK;
      break;

    case GSASL_PASSCODE:
      if (args_info.passcode_arg == NULL)
	args_info.passcode_arg = readutf8pass ("Enter passcode: ");

      gsasl_property_set (sctx, GSASL_PASSCODE, args_info.passcode_arg);

      rc = GSASL_OK;
      break;

    case GSASL_AUTHID:
      if (args_info.authentication_id_arg == NULL)
	{
#if HAVE_GETPWUID
	  uid_t uid;
	  struct passwd *pw;

	  uid = getuid ();
	  pw = getpwuid (uid);

	  if (pw && pw->pw_name)
	    {
	      printf ("Using system username `%s' as "
		      "authentication identity.\n", pw->pw_name);
	      args_info.authentication_id_arg = xstrdup (pw->pw_name);
	    }
	  else
#endif
	    args_info.authentication_id_arg =
	      readutf8line ("Enter authentication ID: ");
	}

      gsasl_property_set (sctx, GSASL_AUTHID,
			  args_info.authentication_id_arg);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHZID:
      gsasl_property_set (sctx, GSASL_AUTHZID,
			  args_info.authorization_id_arg);
      rc = GSASL_OK;
      break;

    case GSASL_SERVICE:
      if (args_info.service_arg == NULL)
	args_info.service_arg =
	  readutf8line ("Enter GSSAPI service name (e.g. \"imap\"): ");

      gsasl_property_set (sctx, GSASL_SERVICE, args_info.service_arg);

      rc = GSASL_OK;
      break;

    case GSASL_HOSTNAME:
      if (args_info.hostname_arg == NULL)
	args_info.hostname_arg = readutf8line ("Enter hostname of server: ");

      gsasl_property_set (sctx, GSASL_HOSTNAME, args_info.hostname_arg);

      rc = GSASL_OK;
      break;

    case GSASL_REALM:
      if (args_info.realm_arg == NULL)
	args_info.realm_arg =
	  readutf8line ("Enter realm of server (optional): ");

      if (args_info.realm_arg && *args_info.realm_arg)
	gsasl_property_set (sctx, GSASL_REALM, args_info.realm_arg);

      rc = GSASL_OK;
      break;

    case GSASL_QOP:
      if (args_info.quality_of_protection_arg == NULL)
	args_info.quality_of_protection_arg = readutf8line
	  ("Enter quality of protection (optional, e.g. 'qop-int'): ");
      if (args_info.quality_of_protection_arg
	  && *args_info.quality_of_protection_arg)
	gsasl_property_set (sctx, GSASL_QOP,
			    args_info.quality_of_protection_arg);
      rc = GSASL_OK;
      break;

    case GSASL_VALIDATE_GSSAPI:
      {
	char *str;
	printf ("Authzid: %s\nDisplay Name: %s\n",
		gsasl_property_fast (sctx, GSASL_AUTHZID),
		gsasl_property_fast (sctx, GSASL_GSSAPI_DISPLAY_NAME));
	str = readutf8line ("Validate GSS-API user? (y/n) ");
	if (strcmp (str, "y") == 0 || strcmp (str, "Y") == 0)
	  rc = GSASL_OK;
	else
	  rc = GSASL_AUTHENTICATION_ERROR;
	free (str);
      }
      break;

    case GSASL_SCRAM_SALTED_PASSWORD:
    case GSASL_SCRAM_ITER:
    case GSASL_SCRAM_SALT:
      break;

    case GSASL_SAML20_IDP_IDENTIFIER:
      {
	char *str = readutf8line ("Enter SAML authentication identifier "
				  "(e.g. \"http://example.org/\"): ");

	gsasl_property_set (sctx, GSASL_SAML20_IDP_IDENTIFIER, str);

	rc = GSASL_OK;
      }
      break;

    case GSASL_AUTHENTICATE_IN_BROWSER:
      {
	const char *url = gsasl_property_get (sctx, GSASL_REDIRECT_URL);

	printf ("Visit this URL to proceed with authentication:\n%s\n", url);

	rc = GSASL_OK;
      }
      break;

    default:
      fprintf (stderr,
	       "warning: mechanism requested unsupported property `%d'\n",
	       prop);
      break;
    }

  return rc;
}
