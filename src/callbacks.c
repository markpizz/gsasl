/* callbacks.c --- Implementation of gsasl callbacks.
 * Copyright (C) 2002, 2003  Simon Josefsson
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

struct gengetopt_args_info args_info;

#define MAX_LINE_LENGTH BUFSIZ

static char *
readline (const char *prompt)
{
  static char line[MAX_LINE_LENGTH];

  printf ("%s", prompt);

  line[0] = '\0';
  fgets (line, MAX_LINE_LENGTH, stdin);
  line[strlen (line) - 1] = '\0';

  return line;
}

static int
utf8cpy (char *dst, size_t * dstlen, char *src, size_t srclen)
{
  int nonasciiflag = 0;
  size_t i;
  char *p = NULL;

  if (srclen != strlen (src))
    return !GSASL_OK;

#if WITH_STRINGPREP
  p = stringprep_locale_to_utf8 (src);
#endif

  if (p)
    {
      size_t len = strlen (p);

      if (dst && *dstlen < len)
	return GSASL_TOO_SMALL_BUFFER;
      *dstlen = len;
      if (dst)
	strcpy (dst, p);
      return GSASL_OK;
    }

#if WITH_STRINGPREP
  fprintf (stderr, " ** failed to convert data from %s to UTF-8\n",
	   stringprep_locale_charset ());
  fprintf (stderr, " ** check the system locale configuration\n");
  fprintf (stderr, " ** treating input as ASCII\n");
#endif

  if (dst && *dstlen < srclen)
    return GSASL_TOO_SMALL_BUFFER;

  *dstlen = srclen;
  for (i = 0; i < srclen; i++)
    {
      if (src[i] & 0x80)
	nonasciiflag = 1;
      if (dst)
	dst[i] = src[i] & 0x7F;
    }

  if (nonasciiflag)
    {
      fprintf (stderr, " ** bit 8 stripped from string\n");
      fprintf (stderr, " ** original string: `%s'\n", src);
      fprintf (stderr, " ** stripped string: `%s'\n", dst);
    }

  return GSASL_OK;
}

/* Client callbacks */

int
client_callback_anonymous (Gsasl_session_ctx * ctx,
			   char *out, size_t * outlen)
{
  int rc;

  if (args_info.anonymous_token_arg == NULL)
    args_info.anonymous_token_arg =
      strdup (readline ("Enter anonymous token (e.g., email address): "));

  if (args_info.anonymous_token_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, args_info.anonymous_token_arg,
		strlen (args_info.anonymous_token_arg));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
client_callback_authorization_id (Gsasl_session_ctx * ctx,
				  char *out, size_t * outlen)
{
  int rc;

  if (args_info.authorization_id_arg == NULL)
    args_info.authorization_id_arg = strdup (readline ("Enter authorization ID: "));

  if (args_info.authorization_id_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, args_info.authorization_id_arg, strlen (args_info.authorization_id_arg));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
client_callback_authentication_id (Gsasl_session_ctx * ctx,
				   char *out, size_t * outlen)
{
  int rc;

  if (args_info.authentication_id_arg == NULL)
    args_info.authentication_id_arg = strdup (readline ("Enter authentication ID: "));

  if (args_info.authentication_id_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, args_info.authentication_id_arg, strlen (args_info.authentication_id_arg));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
client_callback_password (Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
  int rc;

  if (args_info.password_arg == NULL)
    args_info.password_arg = strdup (readline ("Enter password: "));

  if (args_info.password_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, args_info.password_arg, strlen (args_info.password_arg));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
client_callback_service (Gsasl_session_ctx * ctx,
			 char *srv,
			 size_t * srvlen,
			 char *host,
			 size_t * hostlen, char *srvname, size_t * srvnamelen)
{
  int rc;

  if (args_info.service_arg == NULL)
    args_info.service_arg =
      strdup (readline ("Enter GSSAPI service name (e.g. \"imap\"): "));

  if (args_info.hostname_arg == NULL)
    args_info.hostname_arg = strdup (readline ("Enter hostname of server: "));

  if (srvnamelen && args_info.service_name_arg == NULL)
    args_info.service_name_arg =
      strdup (readline ("Enter generic server name (optional): "));

  if (args_info.service_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  if (args_info.hostname_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  if (srvnamelen && args_info.service_name_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (srv, srvlen, args_info.service_arg,
		strlen (args_info.service_arg));
  if (rc != GSASL_OK)
    return rc;

  rc = utf8cpy (host, hostlen, args_info.hostname_arg, strlen (args_info.hostname_arg));
  if (rc != GSASL_OK)
    return rc;

  if (srvnamelen)
    {
      rc = utf8cpy (srvname, srvnamelen, args_info.service_name_arg, strlen (args_info.service_name_arg));
      if (rc != GSASL_OK)
	return rc;
    }

  return GSASL_OK;
}

int
client_callback_passcode (Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
  int rc;

  if (args_info.passcode_arg == NULL)
    args_info.passcode_arg = strdup (readline ("Enter passcode: "));

  if (args_info.passcode_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, args_info.passcode_arg, strlen (args_info.passcode_arg));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

Gsasl_qop
client_callback_qop (Gsasl_session_ctx * ctx, Gsasl_qop serverqops)
{
  int qop = 0;

  if (args_info.quality_of_protection_given)
    {
      if (strcmp (args_info.quality_of_protection_arg, "auth") == 0)
	qop = GSASL_QOP_AUTH;
      else if (strcmp (args_info.quality_of_protection_arg, "auth-int") == 0)
	qop = GSASL_QOP_AUTH_INT;
      else if (strcmp (args_info.quality_of_protection_arg, "auth-conf") == 0)
	qop = GSASL_QOP_AUTH_CONF;
    }

  if (!(serverqops & qop))
    fprintf (stderr,
	     "Warning: Server QOPs %d does not include client QOP %d.\n",
	     serverqops, qop);
  return qop;
}

size_t
client_callback_maxbuf (Gsasl_session_ctx * ctx, size_t servermaxbuf)
{
  return args_info.maxbuf_arg;
}

int
client_callback_realm (Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
  int rc;

  if (args_info.realm_given == 0)
    {
      args_info.realm_arg = malloc (sizeof (*args_info.realm_arg));
      memset (args_info.realm_arg, 0, sizeof (*args_info.realm_arg));
    }

  if (args_info.realm_arg[0] == NULL)
    args_info.realm_arg[0] = strdup (readline ("Enter client realm: "));

  if (args_info.realm_arg[0] == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, args_info.realm_arg[0], strlen (args_info.realm_arg[0]));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

/* Server callbacks */

int
server_callback_cram_md5 (Gsasl_session_ctx * ctx,
			  char *username, char *challenge, char *response)
{
  char *data;

  printf ("User: `%s'\nChallenge: `%s'\nResponse: `%s'\n",
	  username, challenge, response);

  data = readline ("Admit user? (y/n) ");

  if (*data == 'y' || *data == 'Y')
    return GSASL_OK;
  else
    return GSASL_AUTHENTICATION_ERROR;
}

int
server_callback_anonymous (Gsasl_session_ctx * ctx, const char *message)
{
  char *data;

  printf ("Anonymous user: `%s'\n", message);

  data = readline ("Admit user? (y/n) ");

  if (*data == 'y' || *data == 'Y')
    return GSASL_OK;
  else
    return GSASL_AUTHENTICATION_ERROR;
}

Gsasl_qop
server_callback_qop (Gsasl_session_ctx * ctx)
{
  return GSASL_QOP_AUTH | GSASL_QOP_AUTH_INT | GSASL_QOP_AUTH_CONF;
}

size_t
server_callback_maxbuf (Gsasl_session_ctx * ctx)
{
  return args_info.maxbuf_arg;
}

int
server_callback_realm (Gsasl_session_ctx * ctx,
		       char *out, size_t * outlen, size_t nth)
{
  int rc;

  if (args_info.realm_given == 0)
    {
      struct hostent *he;
      char hostname[BUFSIZ];

      rc = gethostname (hostname, BUFSIZ);
      hostname[BUFSIZ - 1] = '\0';
      if (rc != 0)
	return GSASL_NO_MORE_REALMS;

      he = gethostbyname (hostname);
      if (he && strlen (he->h_name) < BUFSIZ)
	strcpy (hostname, he->h_name);

      args_info.realm_arg = malloc (sizeof (*args_info.realm_arg));
      if (args_info.realm_arg == NULL)
	return GSASL_MALLOC_ERROR;
      args_info.realm_arg[args_info.realm_given++] = strdup (hostname);
    }

  if (nth >= args_info.realm_given)
    return GSASL_NO_MORE_REALMS;

  rc = utf8cpy (out, outlen, args_info.realm_arg[nth], strlen (args_info.realm_arg[nth]));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
server_callback_external (Gsasl_session_ctx * ctx)
{
  char *data;

  printf ("Validation information provided out of band (e.g., TLS)\n");

  data = readline ("Admit user? (y/n) ");

  if (*data == 'y' || *data == 'Y')
    return GSASL_OK;
  else
    return GSASL_AUTHENTICATION_ERROR;
}

int
server_callback_validate (Gsasl_session_ctx * ctx,
			  const char *authorization_id,
			  const char *authentication_id, const char *password)
{
  char *data;

  if (authorization_id && strlen (authorization_id) > 0)
    printf ("Authorization ID: %s\n", authorization_id);
  else
    printf ("No authorization ID\n");

  if (authentication_id && strlen (authentication_id) > 0)
    printf ("Authentication ID: %s\n", authentication_id);
  else
    printf ("No authentication ID\n");

  if (password && strlen (password) > 0)
    printf ("Password: %s\n", password);
  else
    printf ("No password\n");

  data = readline ("Admit user? (y/n) ");

  if (*data == 'y' || *data == 'Y')
    return GSASL_OK;
  else
    return GSASL_AUTHENTICATION_ERROR;
}

int
server_callback_retrieve (Gsasl_session_ctx * ctx,
			  const char *authentication_id,
			  const char *authorization_id,
			  const char *realm, char *key, size_t * keylen)
{
  int rc;

  if (authentication_id && strlen (authentication_id) > 0)
    printf ("Authentication ID: %s\n", authentication_id);
  else
    printf ("No authentication ID\n");

  if (authorization_id && strlen (authorization_id) > 0)
    printf ("Authorization ID: %s\n", authorization_id);
  else
    printf ("No authorization ID\n");

  if (realm && strlen (realm) > 0)
    printf ("Realm: %s\n", realm);
  else
    printf ("No realm\n");

  if (args_info.password_arg == NULL)
    args_info.password_arg = strdup (readline ("Enter password: "));

  if (args_info.password_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (key, keylen, args_info.password_arg, strlen (args_info.password_arg));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
server_callback_service (Gsasl_session_ctx * ctx,
			 char *srv,
			 size_t * srvlen, char *host, size_t * hostlen)
{
  int rc;

  if (args_info.service_arg == NULL)
    args_info.service_arg =
      strdup (readline ("Enter GSSAPI service name (e.g. \"imap\"): "));

  if (args_info.hostname_arg == NULL)
    args_info.hostname_arg = strdup (readline ("Enter hostname of server: "));

  if (args_info.service_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  if (args_info.hostname_arg == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (srv, srvlen, args_info.service_arg,
		strlen (args_info.service_arg));
  if (rc != GSASL_OK)
    return rc;

  rc = utf8cpy (host, hostlen, args_info.hostname_arg, strlen (args_info.hostname_arg));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
server_callback_gssapi (Gsasl_session_ctx * ctx,
			const char *client_name,
			const char *authentication_id)
{
  char *data;

  if (client_name)
    printf ("GSSAPI user: %s\n", client_name);

  if (authentication_id)
    printf ("Authentication ID: %s\n", authentication_id);

  data = readline ("Admit user? (y/n) ");

  if (*data == 'y' || *data == 'Y')
    return GSASL_OK;
  else
    return GSASL_AUTHENTICATION_ERROR;
}
