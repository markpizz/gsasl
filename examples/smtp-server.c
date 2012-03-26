/* smtp-server.c --- Example SMTP server with SASL authentication
 * Copyright (C) 2012  Simon Josefsson
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

/* This is a minimal SMTP server with GNU SASL authentication support.
   The only valid password is "sesam".  This server will complete
   authentications using LOGIN, PLAIN, DIGEST-MD5, CRAM-MD5, and
   SCRAM-SHA-1.  It accepts an optional command line parameter
   specifying the service name (i.e., a numerical port number or
   /etc/services name).  By default it listens on port "2000".  */

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netdb.h>
#include <signal.h>

#include <gsasl.h>

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  switch (prop)
    {
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
    }

  printf ("C: %s\n", *line);

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

  print (fh, "235 OK\n");

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

  rc = gsasl_init (&ctx);
  if (rc < 0)
    {
      printf ("gsasl_init (%d): %s\n", rc, gsasl_strerror (rc));
      exit (EXIT_FAILURE);
    }

  printf ("smtp-server [gsasl header %s library %s]\n",
	  GSASL_VERSION, gsasl_check_version (NULL));

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
      socklen_t fromlen;
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
