/* callbacks.c	implementation of gsasl callbacks
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

#define MAX_LINE_LENGTH BUFSIZ

extern int silent;
extern int verbose;
extern char *anonymous_token;
extern char *authentication_id;
extern char *authorization_id;
extern char *password;
extern char *passcode;
extern char *mechanism;
extern char *service;
extern char *hostname;
extern char *servicename;
extern char **realms;
extern size_t nrealms;
extern size_t maxbuf;
extern int qop;

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

  if (anonymous_token == NULL)
    anonymous_token =
      strdup (readline ("Enter anonymous token (e.g., email address): "));

  if (anonymous_token == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, anonymous_token, strlen (anonymous_token));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
client_callback_authorization_id (Gsasl_session_ctx * ctx,
				  char *out, size_t * outlen)
{
  int rc;

  if (authorization_id == NULL)
    authorization_id = strdup (readline ("Enter authorization ID: "));

  if (authorization_id == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, authorization_id, strlen (authorization_id));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
client_callback_authentication_id (Gsasl_session_ctx * ctx,
				   char *out, size_t * outlen)
{
  int rc;

  if (authentication_id == NULL)
    authentication_id = strdup (readline ("Enter authentication ID: "));

  if (authentication_id == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, authentication_id, strlen (authentication_id));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

int
client_callback_password (Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
  int rc;

  if (password == NULL)
    password = strdup (readline ("Enter password: "));

  if (password == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, password, strlen (password));
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

  if (service == NULL)
    service =
      strdup (readline ("Enter GSSAPI service name (e.g. \"imap\"): "));

  if (hostname == NULL)
    hostname = strdup (readline ("Enter hostname of server: "));

  if (srvnamelen && servicename == NULL)
    servicename =
      strdup (readline ("Enter generic server name (optional): "));

  if (service == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  if (hostname == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  if (srvnamelen && servicename == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (srv, srvlen, service, strlen (service));
  if (rc != GSASL_OK)
    return rc;

  rc = utf8cpy (host, hostlen, hostname, strlen (hostname));
  if (rc != GSASL_OK)
    return rc;

  if (srvnamelen)
    {
      rc = utf8cpy (srvname, srvnamelen, servicename, strlen (servicename));
      if (rc != GSASL_OK)
	return rc;
    }

  return GSASL_OK;
}

int
client_callback_passcode (Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
  int rc;

  if (passcode == NULL)
    passcode = strdup (readline ("Enter passcode: "));

  if (passcode == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, passcode, strlen (passcode));
  if (rc != GSASL_OK)
    return rc;

  return GSASL_OK;
}

Gsasl_qop
client_callback_qop (Gsasl_session_ctx * ctx, Gsasl_qop serverqops)
{
  if (!(serverqops & qop))
    fprintf (stderr,
	     "Warning: Server QOPs %d does not include client QOP %d.\n",
	     serverqops, qop);
  return qop;
}

size_t
client_callback_maxbuf (Gsasl_session_ctx * ctx, size_t servermaxbuf)
{
  return maxbuf;
}

int
client_callback_realm (Gsasl_session_ctx * ctx, char *out, size_t * outlen)
{
  int rc;

  if (nrealms == 0)
    {
      realms = malloc (sizeof (*realms));
      memset (realms, 0, sizeof (*realms));
    }

  if (realms[0] == NULL)
    realms[0] = strdup (readline ("Enter client realm: "));

  if (realms[0] == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (out, outlen, realms[0], strlen (realms[0]));
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
  return maxbuf;
}

int
server_callback_realm (Gsasl_session_ctx * ctx,
		       char *out, size_t * outlen, size_t nth)
{
  int rc;

  if (nrealms == 0)
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

      realms = malloc (sizeof (*realms));
      if (realms == NULL)
	return GSASL_MALLOC_ERROR;
      realms[nrealms++] = strdup (hostname);
    }

  if (nth >= nrealms)
    return GSASL_NO_MORE_REALMS;

  rc = utf8cpy (out, outlen, realms[nth], strlen (realms[nth]));
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

  if (password == NULL)
    password = strdup (readline ("Enter password: "));

  if (password == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (key, keylen, password, strlen (password));
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

  if (service == NULL)
    service =
      strdup (readline ("Enter GSSAPI service name (e.g. \"imap\"): "));

  if (hostname == NULL)
    hostname = strdup (readline ("Enter hostname of server: "));

  if (service == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  if (hostname == NULL)
    return GSASL_AUTHENTICATION_ERROR;

  rc = utf8cpy (srv, srvlen, service, strlen (service));
  if (rc != GSASL_OK)
    return rc;

  rc = utf8cpy (host, hostlen, hostname, strlen (hostname));
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
