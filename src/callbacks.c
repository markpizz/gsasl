/* callbacks.c --- Implementation of gsasl callbacks.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"
#include "callbacks.h"

#ifdef HAVE_READLINE_READLINE_H
# include <readline/readline.h>
#else
extern char *readline (const char *prompt);
#endif

#include "iconvme.h"

static char *
locale_to_utf8 (char *str)
{
#if HAVE_LANGINFO_CODESET
  if (str)
    {
      char *from = nl_langinfo (CODESET);
      char *q = iconv_z (from, "UTF-8", str);
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
	  uid_t uid;
	  struct passwd *pw;

	  uid = getuid ();
	  pw = getpwuid (uid);

	  if (pw && pw->pw_name)
	    {
	      printf ("Using system username `%s' as "
		      "authentication identity.\n", pw->pw_name);
	      args_info.authentication_id_arg = strdup (pw->pw_name);
	    }
	  else
	    args_info.authentication_id_arg =
	      readutf8line ("Enter authentication ID: ");
	}

      gsasl_property_set (sctx, GSASL_AUTHID, args_info.authentication_id_arg);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHZID:
      gsasl_property_set (sctx, GSASL_AUTHZID, args_info.authorization_id_arg);
      rc = GSASL_OK;
      break;

    default:
      printf ("Mechanism requested unsupported property `%d'.\n", prop);
      break;
    }

  return rc;
}
