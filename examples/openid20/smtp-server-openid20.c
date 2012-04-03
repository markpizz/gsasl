/* smtp-server-openid20.c --- Example SMTP server with OpenID 2.0 support
 * Copyright (C) 2012 Simon Josefsson
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

#include <config.h>

/* This is based on ../smtp-server.c but adds support for OpenID 2.0.
   See README for instructions. */

/* This is a minimal SMTP server with GNU SASL authentication support.
   The only valid password is "sesam".  This server will complete
   authentications using LOGIN, PLAIN, DIGEST-MD5, CRAM-MD5, and
   SCRAM-SHA-1.  It accepts an optional command line parameter
   specifying the service name (i.e., a numerical port number or
   /etc/services name).  By default it listens on port "2000".  */

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netdb.h>
#include <signal.h>

#include <gsasl.h>

static char *store_path;
static char *realm;
static char *return_to;

static void
hex_encode (char *dst, const char *src, size_t len)
{
  static const char trans[] = "0123456789abcdef";

  while (len--)
    {
      *dst++ = trans[(*src >> 4) & 0xf];
      *dst++ = trans[*src++ & 0xf];
    }

  *dst = '\0';
}

static int
write_file (const char *filename, const char *data)
{
  FILE *fh;

  fh = fopen (filename, "w");
  if (!fh)
    {
      perror ("fopen");
      return -1;
    }

  if (fputs (data, fh) <= 0)
    return -1;

  if (fclose (fh) != 0)
    return -1;

  return 0;
}

static char *
get_redirect_url (Gsasl_session * sctx)
{
  FILE *fh;
  char *tmp, *tmp2;
  char *line = NULL;
  size_t n = 0;
  const char *nonce = gsasl_session_hook_get (sctx);
  int rc;

  rc = asprintf (&tmp, "%s", store_path);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  mkdir (tmp, 0770);
  free (tmp);

  rc = asprintf (&tmp, "%s/state", store_path);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  mkdir (tmp, 0770);
  free (tmp);

  rc = asprintf (&tmp, "%s/state/%s", store_path, nonce);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  mkdir (tmp, 0770);
  free (tmp);

  rc = asprintf (&tmp, "%s/state/%s/openid_url", store_path, nonce);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  if (write_file (tmp, gsasl_property_fast (sctx, GSASL_AUTHID)))
    return NULL;
  free (tmp);

  rc = asprintf (&tmp, "%s/state/%s/realm", store_path, nonce);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  if (write_file (tmp, realm))
    return NULL;
  free (tmp);

  rc = asprintf (&tmp, "%s/state/%s/return_to", store_path, nonce);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  rc = asprintf (&tmp2, "%s/%s", return_to, nonce);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  if (write_file (tmp, tmp2))
    return NULL;
  free (tmp);
  free (tmp2);

  rc =
    asprintf (&tmp, "gsasl-openid20-redirect.php %s %s", store_path, nonce);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  fh = popen (tmp, "r");
  free (tmp);
  if (!fh)
    {
      perror ("popen");
      return NULL;
    }
  while (getline (&line, &n, fh) >= 0)
    printf ("gsasl-openid20-redirect.php: %s", line);
  pclose (fh);

  rc = asprintf (&tmp, "%s/state/%s/redirect_url", store_path, nonce);
  if (rc <= 0)
    {
      perror ("asprintf");
      return NULL;
    }
  fh = fopen (tmp, "r");
  if (!fh)
    {
      perror ("fopen");
      return NULL;
    }
  if (getline (&line, &n, fh) <= 0)
    {
      perror ("getline");
      return NULL;
    }
  fclose (fh);

  return line;
}

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;
  FILE *fh;
  char *line = NULL;
  size_t n = 0;
  const char *nonce = gsasl_session_hook_get (sctx);
  char *tmp;

  switch (prop)
    {
    case GSASL_REDIRECT_URL:
      {
	line = get_redirect_url (sctx);
	if (line == NULL)
	  rc = GSASL_AUTHENTICATION_ERROR;
	else
	  {
	    rc = GSASL_OK;
	    gsasl_property_set (sctx, prop, line);
	  }
      }
      break;

    case GSASL_VALIDATE_OPENID20:
      {
	time_t start = time (NULL);

	rc = GSASL_AUTHENTICATION_ERROR;
	do
	  {
	    sleep (1);

	    rc = asprintf (&tmp, "%s/state/%s/success", store_path, nonce);
	    if (rc <= 0)
	      {
		perror ("asprintf");
		break;
	      }
	    fh = fopen (tmp, "r");
	    free (tmp);
	    if (!fh)
	      {
		rc = asprintf (&tmp, "%s/state/%s/fail", store_path, nonce);
		if (rc <= 0)
		  {
		    perror ("asprintf");
		    break;
		  }
		fh = fopen (tmp, "r");
		free (tmp);
		if (!fh)
		  {
		    puts ("waiting");
		    continue;
		  }

		if (getline (&line, &n, fh) > 0)
		  printf ("fail: %s\n", line);
		fclose (fh);

		rc = GSASL_AUTHENTICATION_ERROR;
		break;
	      }

	    if (getline (&line, &n, fh) > 0)
	      printf ("claimed id: %s\n", line);
	    fclose (fh);

	    gsasl_property_set (sctx, GSASL_AUTHID, line);

	    rc = asprintf (&tmp, "%s/state/%s/sreg", store_path, nonce);
	    if (rc <= 0)
	      {
		perror ("asprintf");
		break;
	      }
	    fh = fopen (tmp, "r");
	    free (tmp);
	    if (fh)
	      {
		if (getline (&line, &n, fh) > 0)
		  {
		    printf ("sreg: %s\n", line);
		    gsasl_property_set (sctx, GSASL_OPENID20_OUTCOME_DATA,
					line);
		  }
		fclose (fh);
	      }

	    rc = GSASL_OK;
	    break;
	  }
	while (time (NULL) - start < 30);
      }
      break;

    case GSASL_PASSWORD:
      gsasl_property_set (sctx, prop, "sesam");
      rc = GSASL_OK;
      break;

    default:
      /* You may want to log (at debug verbosity level) that an
         unknown property was requested here, possibly after filtering
         known rejected property requests. */
      break;
    }

  return rc;
}

static ssize_t
gettrimline (char **line, size_t * n, FILE * fh)
{
  ssize_t s = getline (line, n, fh);

  if (s >= 2)
    {
      if ((*line)[strlen (*line) - 1] == '\n')
	(*line)[strlen (*line) - 1] = '\0';
      if ((*line)[strlen (*line) - 1] == '\r')
	(*line)[strlen (*line) - 1] = '\0';

      printf ("C: %s\n", *line);
    }

  return s;
}

#define print(fh, ...)							\
  printf ("S: "), printf (__VA_ARGS__), fprintf (fh, __VA_ARGS__)

static void
server_auth (FILE * fh, Gsasl_session * session)
{
  char *line = NULL;
  size_t n = 0;
  char *p;
  int rc;
  /* The nonce value MUST be at least 2^32 large and large enough to
     handle well in excess of the number of concurrent transactions a
     SASL server shall see. */
  char bin_nonce[32];
  char nonce[2 * sizeof (bin_nonce) + 1];

  gsasl_nonce (bin_nonce, sizeof (bin_nonce));
  hex_encode (nonce, bin_nonce, sizeof (bin_nonce));
  gsasl_session_hook_set (session, nonce);

  /* The ordering and the type of checks in the following loop has to
     be adapted for each protocol depending on its SASL properties.
     SMTP is a "server-first" SASL protocol.  This implementation do
     not support piggy-backing of the initial client challenge nor
     piggy-backing of the terminating server response.  See RFC 2554
     and RFC 4422 for terminology.  That profile results in the
     following loop structure.  Ask on the help-gsasl list if you are
     uncertain.  */
  do
    {
      rc = gsasl_step64 (session, line, &p);
      if (rc == GSASL_NEEDS_MORE || (rc == GSASL_OK && p && *p))
	{
	  print (fh, "334 %s\n", p);
	  gsasl_free (p);

	  if (gettrimline (&line, &n, fh) < 0)
	    {
	      print (fh, "221 localhost getline failure\n");
	      goto done;
	    }
	}
    }
  while (rc == GSASL_NEEDS_MORE);

  if (rc != GSASL_OK)
    {
      print (fh, "535 gsasl_step64 (%d): %s\n", rc, gsasl_strerror (rc));
      goto done;
    }

  {
    const char *authid = gsasl_property_fast (session, GSASL_AUTHID);
    const char *authzid = gsasl_property_fast (session, GSASL_AUTHZID);
    print (fh, "235 OK [authid: %s authzid: %s]\n",
	   authid ? authid : "N/A", authzid ? authzid : "N/A");
  }

done:
  free (line);
}

static void
smtp (FILE * fh, Gsasl * ctx)
{
  char *line = NULL;
  size_t n = 0;
  int rc;

  print (fh, "220 localhost ESMTP GNU SASL smtp-server\n");

  while (gettrimline (&line, &n, fh) >= 0)
    {
      if (strncmp (line, "EHLO ", 5) == 0 || strncmp (line, "ehlo ", 5) == 0)
	{
	  char *mechlist;

	  rc = gsasl_server_mechlist (ctx, &mechlist);
	  if (rc != GSASL_OK)
	    {
	      print (fh, "221 localhost gsasl_server_mechlist (%d): %s\n",
		     rc, gsasl_strerror (rc));
	      goto done;
	    }

	  print (fh, "250-localhost\n");
	  print (fh, "250 AUTH %s\n", mechlist);

	  gsasl_free (mechlist);
	}
      else if (strncmp (line, "AUTH ", 5) == 0
	       || strncmp (line, "auth ", 5) == 0)
	{
	  Gsasl_session *session = NULL;

	  if ((rc = gsasl_server_start (ctx, line + 5, &session)) != GSASL_OK)
	    {
	      print (fh, "221 localhost gsasl_server_start (%d): %s\n",
		     rc, gsasl_strerror (rc));
	      goto done;
	    }

	  server_auth (fh, session);

	  gsasl_finish (session);
	}
      else if (strncmp (line, "QUIT", 4) == 0
	       || strncmp (line, "quit", 4) == 0)
	{
	  print (fh, "221 localhost QUIT\n");
	  goto done;
	}
      else
	print (fh, "500 unrecognized command\n");
    }

  print (fh, "221 localhost getline failure\n");

done:
  free (line);
}

int
main (int argc, char *argv[])
{
  const char *service = argc > 1 ? argv[1] : "2000";
  volatile int run = 1;
  struct addrinfo hints, *addrs;
  int sockfd;
  int rc;
  int yes = 1;
  Gsasl *ctx;

  setvbuf (stdout, NULL, _IONBF, 0);

  if (argc != 5)
    {
      printf ("Usage: %s PORT STORE-PATH REALM RETURN-TO\n", argv[0]);
      exit (EXIT_FAILURE);
    }
  store_path = argv[2];
  realm = argv[3];
  return_to = argv[4];

  rc = gsasl_init (&ctx);
  if (rc < 0)
    {
      printf ("gsasl_init (%d): %s\n", rc, gsasl_strerror (rc));
      exit (EXIT_FAILURE);
    }

  printf ("%s [gsasl header %s library %s]\n",
	  argv[0], GSASL_VERSION, gsasl_check_version (NULL));

  gsasl_callback_set (ctx, callback);

  memset (&hints, 0, sizeof (hints));
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
  hints.ai_socktype = SOCK_STREAM;

  rc = getaddrinfo (NULL, service, &hints, &addrs);
  if (rc < 0)
    {
      printf ("getaddrinfo: %s\n", gai_strerror (rc));
      exit (EXIT_FAILURE);
    }

  sockfd = socket (addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
  if (sockfd < 0)
    {
      perror ("socket");
      exit (EXIT_FAILURE);
    }

  if (setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes)) < 0)
    {
      perror ("setsockopt");
      exit (EXIT_FAILURE);
    }

  rc = bind (sockfd, addrs->ai_addr, addrs->ai_addrlen);
  if (rc < 0)
    {
      perror ("bind");
      exit (EXIT_FAILURE);
    }

  freeaddrinfo (addrs);

  rc = listen (sockfd, SOMAXCONN);
  if (rc < 0)
    {
      perror ("listen");
      exit (EXIT_FAILURE);
    }

  signal (SIGPIPE, SIG_IGN);

  while (run)
    {
      struct sockaddr from;
      socklen_t fromlen = sizeof (from);
      char host[NI_MAXHOST];
      int fd;
      FILE *fh;

      fd = accept (sockfd, &from, &fromlen);
      if (fd < 0)
	{
	  perror ("accept");
	  continue;
	}

      rc = getnameinfo (&from, fromlen, host, sizeof (host),
			NULL, 0, NI_NUMERICHOST);
      if (rc == 0)
	printf ("connection from %s\n", host);
      else
	printf ("getnameinfo: %s\n", gai_strerror (rc));

      fh = fdopen (fd, "w+");
      if (!fh)
	{
	  perror ("fdopen");
	  close (fd);
	  continue;
	}

      smtp (fh, ctx);

      fclose (fh);
    }

  close (sockfd);
  gsasl_done (ctx);

  return 0;
}
