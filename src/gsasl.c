/* gsasl.c --- Command line interface to libgsasl.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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
#include "imap.h"
#include "smtp.h"

#ifdef HAVE_WS2TCPIP_H
# include <ws2tcpip.h>
#endif

#ifdef HAVE_LIBGNUTLS
# include <gnutls/gnutls.h>
gnutls_session session;
bool using_tls = false;
#endif

#define MAX_LINE_LENGTH BUFSIZ

struct gengetopt_args_info args_info;
int sockfd = 0;

int
writeln (const char *str)
{
  printf ("%s\n", str);

  if (sockfd)
    {
      ssize_t len = strlen (str);

#ifdef HAVE_LIBGNUTLS
      if (using_tls)
	{
	  /* GnuTLS < 1.2.9 cannot handle data != NULL && count == 0,
	     it will return an error. */
	  if (len > 0)
	    len = gnutls_record_send (session, str, len);
	  else
	    len = 0;
	}
      else
#endif
	len = write (sockfd, str, len);
      if (len != strlen (str))
	return 0;

#define CRLF "\r\n"

#ifdef HAVE_LIBGNUTLS
      if (using_tls)
	len = gnutls_record_send (session, CRLF, strlen (CRLF));
      else
#endif
	len = write (sockfd, CRLF, strlen (CRLF));
      if (len != strlen (CRLF))
	return 0;
    }

  return 1;
}

int
readln (char **out)
{
  if (sockfd)
    {
      ssize_t len;
      size_t j = 0;
      char input[MAX_LINE_LENGTH];

      /* FIXME: Optimize and remove size limit. */

      do
	{
	  j++;

#ifdef HAVE_LIBGNUTLS
	  if (using_tls)
	    len = gnutls_record_recv (session, &input[j - 1], 1);
	  else
#endif
	    len = recv (sockfd, &input[j - 1], 1, 0);
	  if (len <= 0)
	    return 0;
	}
      while (input[j - 1] != '\n' && j < MAX_LINE_LENGTH);
      input[j] = '\0';

      *out = xstrdup (input);

      printf ("%s", *out);
    }
  else
    {
      *out = readline ("");
      if (*out == NULL)
	return 0;
    }

  return 1;
}

static int
greeting (void)
{
  if (args_info.imap_flag)
    return imap_greeting ();
  if (args_info.smtp_flag)
    return smtp_greeting ();

  return 1;
}

static int
has_starttls (void)
{
  if (args_info.imap_flag)
    return imap_has_starttls ();
  if (args_info.smtp_flag)
    return smtp_has_starttls ();

  return 0;
}

static int
starttls (void)
{
  if (args_info.imap_flag)
    return imap_starttls ();
  if (args_info.smtp_flag)
    return smtp_starttls ();

  return 1;
}

static int
select_mechanism (char **mechlist)
{
  char *in;

  if (args_info.imap_flag)
    return imap_select_mechanism (mechlist);
  if (args_info.smtp_flag)
    return smtp_select_mechanism (mechlist);

  if (args_info.mechanism_arg)
    *mechlist = args_info.mechanism_arg;
  else if (args_info.server_flag)
    {
      if (!args_info.quiet_given)
	fprintf (stderr, _("Choose SASL mechanism:\n"));
      if (!readln (&in))
	return 0;
      *mechlist = in;
    }
  else				/* if (args_info.client_flag) */
    {
      if (!args_info.quiet_given)
	fprintf (stderr,
		 _("Input list of SASL mechanisms supported by server:\n"));
      if (!readln (&in))
	return 0;

      *mechlist = in;
    }

  return 1;
}

static int
authenticate (const char *mech)
{
  if (args_info.imap_flag)
    return imap_authenticate (mech);
  if (args_info.smtp_flag)
    return smtp_authenticate (mech);

  if (!args_info.quiet_given)
    fprintf (stderr, _("Using mechanism:\n"));
  puts (mech);

  return 1;
}

static int
step_send (const char *data)
{
  if (args_info.imap_flag)
    return imap_step_send (data);
  if (args_info.smtp_flag)
    return smtp_step_send (data);

  if (!args_info.quiet_given)
    {
      if (args_info.server_flag)
	fprintf (stderr, _("Output from server:\n"));
      else
	fprintf (stderr, _("Output from client:\n"));
    }
  fprintf (stdout, "%s\n", data);

  return 1;
}

static int
step_recv (char **data)
{
  if (args_info.imap_flag)
    return imap_step_recv (data);
  if (args_info.smtp_flag)
    return smtp_step_recv (data);

  if (!readln (data))
    return 0;

  return 1;
}

static int
auth_finish (void)
{
  if (args_info.imap_flag)
    return imap_auth_finish ();
  if (args_info.smtp_flag)
    return smtp_auth_finish ();

  return 1;
}

static int
logout (void)
{
  if (args_info.imap_flag)
    return imap_logout ();
  if (args_info.smtp_flag)
    return smtp_logout ();

  return 1;
}

const char version_etc_copyright[] =
  /* Do *not* mark this string for translation.  %s is a copyright
     symbol suitable for this locale, and %d is the copyright
     year.  */
  "Copyright %s %d Simon Josefsson.";

static void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      cmdline_parser_print_help ();
      emit_bug_reporting_address ();
    }
  exit (status);
}

int
main (int argc, char *argv[])
{
  Gsasl *ctx = NULL;
  int res;
  char *in;
  char *connect_hostname = NULL;
  char *connect_service = NULL;
#ifdef HAVE_LIBGNUTLS
  gnutls_anon_client_credentials anoncred;
  gnutls_certificate_credentials x509cred;
#endif

  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

#ifdef HAVE_WS2TCPIP_H
  {
    WORD wVersionRequested;
    WSADATA wsaData;
    int r;

    wVersionRequested = MAKEWORD (2, 0);
    r = WSAStartup (wVersionRequested, &wsaData);
    if (r)
      error (EXIT_FAILURE, 0, _("cannot initialize Windows sockets"));
  }
#endif

  if (cmdline_parser (argc, argv, &args_info) != 0)
    return EXIT_FAILURE;

  if (args_info.version_given)
    {
      const char *p = PACKAGE_NAME;
      if (strcmp (gsasl_check_version (NULL), PACKAGE_VERSION) != 0)
	p = PACKAGE_STRING;
      version_etc (stdout, "gsasl", p, gsasl_check_version (NULL),
		   "Simon Josefsson", (char *) NULL);
      return EXIT_SUCCESS;
    }

  if (args_info.help_given)
    usage (EXIT_SUCCESS);

  if (!(args_info.client_flag || args_info.client_given) &&
      !args_info.server_given &&
      !args_info.client_mechanisms_flag && !args_info.server_mechanisms_flag)
    {
      error (0, 0, _("missing argument"));
      usage (EXIT_FAILURE);
    }

  if ((args_info.x509_cert_file_arg && !args_info.x509_key_file_arg) ||
      (!args_info.x509_cert_file_arg && args_info.x509_key_file_arg))
    error (EXIT_FAILURE, 0,
	   _("need both --x509-cert-file and --x509-key-file"));

  if (args_info.starttls_flag && args_info.no_starttls_flag)
    error (EXIT_FAILURE, 0,
	   _("cannot use both --starttls and --no-starttls"));

  if (args_info.smtp_flag && args_info.imap_flag)
    error (EXIT_FAILURE, 0, _("cannot use both --smtp and --imap"));

  if (!args_info.connect_given && args_info.inputs_num == 0 &&
      !args_info.client_given && !args_info.server_given &&
      !args_info.client_mechanisms_flag && !args_info.server_mechanisms_flag)
    {
      cmdline_parser_print_help ();
      emit_bug_reporting_address ();
      return EXIT_SUCCESS;
    }

  if (args_info.connect_given)
    {
      if (strrchr (args_info.connect_arg, ':'))
	{
	  connect_hostname = xstrdup (args_info.connect_arg);
	  *strrchr (connect_hostname, ':') = '\0';
	  connect_service = xstrdup (strrchr (args_info.connect_arg, ':') + 1);
	}
      else
	{
	  connect_hostname = xstrdup (args_info.connect_arg);
	  if (args_info.smtp_flag)
	    connect_service = xstrdup ("smtp");
	  else
	    connect_service = xstrdup ("imap");
	}
    }
  else if (args_info.inputs_num > 0)
    {
      connect_hostname = args_info.inputs[0];
      if (args_info.inputs_num > 1)
	connect_service = args_info.inputs[1];
      else if (args_info.smtp_flag)
	connect_service = xstrdup ("smtp");
      else
	connect_service = xstrdup ("imap");
    }

  if (connect_service && !args_info.smtp_flag && !args_info.imap_flag)
    {
      if (strcmp (connect_service, "25") == 0 ||
	  strcmp (connect_service, "smtp") == 0)
	args_info.smtp_flag = 1;
      else
	args_info.imap_flag = 1;
    }

  if (args_info.imap_flag && !args_info.service_given)
    args_info.service_arg = xstrdup ("imap");

  if (args_info.smtp_flag && !args_info.service_given)
    args_info.service_arg = xstrdup ("smtp");

  if (args_info.imap_flag || args_info.smtp_flag)
    args_info.no_client_first_flag = 1;

  if (connect_hostname && !args_info.hostname_arg)
    args_info.hostname_arg = xstrdup (connect_hostname);

  if (!isatty (STDOUT_FILENO))
    setvbuf (stdout, NULL, _IOLBF, BUFSIZ);

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    error (EXIT_FAILURE, 0, _("initialization failure: %s"),
	   gsasl_strerror (res));

  gsasl_callback_set (ctx, callback);

  if (args_info.client_mechanisms_flag || args_info.server_mechanisms_flag)
    {
      char *mechs;

      if (args_info.client_mechanisms_flag)
	res = gsasl_client_mechlist (ctx, &mechs);
      else
	res = gsasl_server_mechlist (ctx, &mechs);

      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, _("error listing mechanisms: %s"),
	       gsasl_strerror (res));

      if (!args_info.quiet_given)
	{
	  if (args_info.client_mechanisms_flag)
	    fprintf (stderr,
		     _("This client supports the following mechanisms:\n"));
	  else
	    fprintf (stderr,
		     _("This server supports the following mechanisms:\n"));
	}

      fprintf (stdout, "%s\n", mechs);

      free (mechs);

      return EXIT_SUCCESS;
    }

  if (args_info.connect_given || args_info.inputs_num > 0)
    {
      struct sockaddr connect_addr;
      struct sockaddr *saddr = &connect_addr;
      size_t saddrlen = sizeof (*saddr);
      struct addrinfo hints;
      struct addrinfo *ai0, *ai;

      memset (&hints, 0, sizeof (hints));
      hints.ai_flags = AI_CANONNAME;
      hints.ai_socktype = SOCK_STREAM;
      res = getaddrinfo (connect_hostname, connect_service, &hints, &ai0);
      if (res != 0)
	error (EXIT_FAILURE, 0, "%s: %s", connect_hostname,
	       gai_strerror (res));

      for (ai = ai0; ai; ai = ai->ai_next)
	{
	  fprintf (stderr, "Trying %s...\n", quote (ai->ai_canonname));

	  sockfd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	  if (sockfd < 0)
	    {
	      error (0, errno, "socket");
	      continue;
	    }

	  if (connect (sockfd, ai->ai_addr, ai->ai_addrlen) < 0)
	    {
	      int save_errno = errno;
	      close (sockfd);
	      sockfd = -1;
	      error (0, save_errno, "connect");
	      continue;
	    }
	  break;
	}

      if (sockfd < 0)
	error (EXIT_FAILURE, errno, "socket");

      saddr = ai->ai_addr;
      saddrlen = ai->ai_addrlen;

      freeaddrinfo (ai);
    }

  if (!greeting ())
    return 1;

#ifdef HAVE_LIBGNUTLS
  if (sockfd && !args_info.no_starttls_flag &&
      (args_info.starttls_flag || has_starttls ()))
    {
      res = gnutls_global_init ();
      if (res < 0)
	error (EXIT_FAILURE, 0, _("GnuTLS global initialization failed: %s"),
	       gnutls_strerror (res));

      res = gnutls_init (&session, GNUTLS_CLIENT);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("GnuTLS initialization failed: %s"),
	       gnutls_strerror (res));

      res = gnutls_set_default_priority (session);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("setting GnuTLS defaults failed: %s"),
	       gnutls_strerror (res));

      res = gnutls_anon_allocate_client_credentials (&anoncred);
      if (res < 0)
	error (EXIT_FAILURE, 0,
	       _("allocating anonymous GnuTLS credential: %s"),
	       gnutls_strerror (res));

      res = gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("setting anonymous GnuTLS credential: %s"),
	       gnutls_strerror (res));

      res = gnutls_certificate_allocate_credentials (&x509cred);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("allocating X.509 GnuTLS credential: %s"),
	       gnutls_strerror (res));

      if (args_info.x509_cert_file_arg && args_info.x509_key_file_arg)
	res = gnutls_certificate_set_x509_key_file
	  (x509cred, args_info.x509_cert_file_arg,
	   args_info.x509_key_file_arg, GNUTLS_X509_FMT_PEM);
      if (res != GNUTLS_E_SUCCESS)
	error (EXIT_FAILURE, 0, _("loading X.509 GnuTLS credential: %s"),
	       gnutls_strerror (res));

      if (args_info.x509_ca_file_arg)
	{
	  res = gnutls_certificate_set_x509_trust_file
	    (x509cred, args_info.x509_ca_file_arg, GNUTLS_X509_FMT_PEM);
	  if (res < 0)
	    error (EXIT_FAILURE, 0, _("no X.509 CAs found: %s"),
		   gnutls_strerror (res));
	  if (res == 0)
	    error (EXIT_FAILURE, 0, _("no X.509 CAs found"));
	}

      res = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE,
				    x509cred);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("setting X.509 GnuTLS credential: %s"),
	       gnutls_strerror (res));

      if (args_info.priority_arg)
	{
	  const char *err_pos;

	  res = gnutls_priority_set_direct (session, args_info.priority_arg,
					    &err_pos);
	  if (res < 0)
	    error (EXIT_FAILURE, 0,
		   _("setting GnuTLS cipher priority (%s): %s\n"),
		   gnutls_strerror (res), err_pos);
	}

      gnutls_transport_set_ptr (session, (gnutls_transport_ptr) sockfd);

      if (!starttls ())
	return 1;

      res = gnutls_handshake (session);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("GnuTLS handshake failed: %s"),
	       gnutls_strerror (res));

      if (args_info.x509_ca_file_arg)
	{
	  unsigned int status;

	  res = gnutls_certificate_verify_peers2 (session, &status);
	  if (res < 0)
	    error (EXIT_FAILURE, 0, _("verifying peer certificate: %s"),
		   gnutls_strerror (res));

	  if (status & GNUTLS_CERT_INVALID)
	    error (EXIT_FAILURE, 0, _("server certificate is not trusted"));

	  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
	    error (EXIT_FAILURE, 0,
		   _("server certificate hasn't got a known issuer"));

	  if (status & GNUTLS_CERT_REVOKED)
	    error (EXIT_FAILURE, 0, _("server certificate has been revoked"));

	  if (status != 0)
	    error (EXIT_FAILURE, 0,
		   _("could not verify server certificate (rc=%d)"), status);
	}

      using_tls = true;
    }
#endif

  if (args_info.client_flag || args_info.client_given
      || args_info.server_given)
    {
      char *out;
      char *b64output;
      size_t output_len;
      size_t b64output_len;
      const char *mech;
      Gsasl_session *xctx = NULL;

      if (!select_mechanism (&in))
	return 1;

      mech = gsasl_client_suggest_mechanism (ctx, in);
      if (mech == NULL)
	{
	  fprintf (stderr, _("Cannot find mechanism...\n"));
	  return 0;
	}

      if (args_info.mechanism_arg)
	mech = args_info.mechanism_arg;

      if (!authenticate (mech))
	return 1;

      /* Authenticate using mechanism */

      if (args_info.server_flag)
	res = gsasl_server_start (ctx, mech, &xctx);
      else
	res = gsasl_client_start (ctx, mech, &xctx);
      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, _("mechanism unavailable: %s"),
	       gsasl_strerror (res));

      in = NULL;
      out = NULL;

      if (!args_info.server_flag && args_info.no_client_first_flag)
	{
	  res = GSASL_NEEDS_MORE;
	  goto no_client_first;
	}

      do
	{
	  res = gsasl_step64 (xctx, in, &out);
	  if (res != GSASL_NEEDS_MORE && res != GSASL_OK)
	    break;

	  if (!step_send (out))
	    return 1;

	  if (res != GSASL_NEEDS_MORE)
	    break;

	no_client_first:
	  if (!args_info.quiet_given &&
	      !args_info.imap_flag && !args_info.smtp_flag)
	    {
	      if (args_info.server_flag)
		fprintf (stderr, _("Enter base64 authentication data "
				   "from client (press RET if none):\n"));
	      else
		fprintf (stderr, _("Enter base64 authentication data "
				   "from server (press RET if none):\n"));
	    }

	  if (!step_recv (&in))
	    return 1;
	}
      while (res == GSASL_NEEDS_MORE);

      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, _("mechanism error: %s"),
	       gsasl_strerror (res));

      if (!auth_finish ())
	return 1;

      if (!args_info.quiet_given)
	{
	  if (args_info.server_flag)
	    fprintf (stderr, _("Server authentication "
			       "finished (client trusted)...\n"));
	  else
	    fprintf (stderr, _("Client authentication "
			       "finished (server trusted)...\n"));
	  fflush (stderr);
	}

      /* Transfer application payload */
      if (args_info.application_data_flag)
	{
	  struct pollfd pfd[2];
	  char *sockbuf = NULL;
	  size_t sockpos = 0;

	  /* Setup pollfd structs... */
	  pfd[0].fd = STDIN_FILENO;
	  pfd[0].events = POLLIN;
	  if (sockfd)
	    {
	      pfd[1].fd = sockfd;
	      pfd[1].events = POLLIN;
	    }

	  if (!args_info.quiet_given)
	    {
	      fprintf (stderr, _("Enter application data (EOF to finish):\n"));
	      fflush (stderr);
	    }

	  while (1)
	    {
	      int rc;

	      pfd[0].revents = 0;
	      pfd[1].revents = 0;

	      rc = poll (pfd, sockfd ? 2 : 1, -1);
	      if (rc < 0 && errno == EINTR)
		continue;

	      /* Always check for errors */
	      if (rc < 0)
		error (EXIT_FAILURE, errno, "poll");

	      /* We got data to read from stdin.. */
	      if ((pfd[0].revents & (POLLIN | POLLERR)) == POLLIN)
		{
		  char *line = NULL;
		  size_t n;
		  ssize_t len;

		  len = getline (&line, &n, stdin);
		  if (len < 0)
		    break;

		  if (args_info.imap_flag || args_info.smtp_flag)
		    {
		      int pos = strlen (line);

		      if (pos < 2 || strcmp (&line[pos-2], "\r\n") != 0)
			{
			  char *tmp = realloc (line, pos + 1);
			  if (!tmp)
			    error (EXIT_FAILURE, errno, "realloc");
			  line = tmp;
			  line[pos - 1] = '\r';
			  line[pos] = '\n';
			  line[pos + 1] = '\0';
			}
		    }
		  else
		    line[strlen (line) - 1] = '\0';

		  res = gsasl_encode (xctx, line, strlen (line),
				      &out, &output_len);
		  if (res != GSASL_OK)
		    break;

		  if (sockfd)
		    {
#ifdef HAVE_LIBGNUTLS
		      if (using_tls)
			len = gnutls_record_send (session, out, output_len);
		      else
#endif
			len = write (sockfd, out, output_len);
		      if (len != output_len)
			error (EXIT_FAILURE, errno, "write");
		    }
		  else if (!(strlen (line) == output_len &&
			     memcmp (line, out, output_len) == 0))
		    {
		      res = gsasl_base64_to (out, output_len,
					     &b64output, &b64output_len);
		      if (res != GSASL_OK)
			break;

		      if (!args_info.quiet_given)
			fprintf (stderr, _("Base64 encoded application "
					   "data to send:\n"));
		      fprintf (stdout, "%s\n", b64output);

		      free (b64output);
		    }

		  free (line);
		  free (out);
		}
	      /* If there was an error, quit.  */
	      else if (pfd[0].revents & (POLLERR | POLLHUP))
		break;

	      /* We got data to read from the socket.. */
	      if (sockfd && (pfd[1].revents & (POLLIN | POLLERR)) == POLLIN)
		{
		  ssize_t len;
		  char *tmp;

		  tmp = realloc (sockbuf, sockpos + 1);
		  if (!tmp)
		    error (EXIT_FAILURE, errno, "realloc");
		  sockbuf = tmp;

#ifdef HAVE_LIBGNUTLS
		  if (using_tls)
		    len = gnutls_record_recv (session, &sockbuf[sockpos], 1);
		  else
#endif
		    len = recv (sockfd, &sockbuf[sockpos], 1, 0);
		  if (len <= 0)
		    break;

		  sockpos++;

		  res = gsasl_decode (xctx, sockbuf, sockpos,
				      &out, &output_len);
		  if (res == GSASL_NEEDS_MORE)
		    continue;
		  if (res != GSASL_OK)
		    break;

		  free (sockbuf);
		  sockbuf = NULL;
		  sockpos = 0;

		  printf("%.*s", output_len, out);
		  free (out);
		}
	      /* If there was an error, quit.  */
	      else if (pfd[1].revents & (POLLERR | POLLHUP))
		break;
	    }

	  if (res != GSASL_OK)
	    error (EXIT_FAILURE, 0, _("encoding error: %s"),
		   gsasl_strerror (res));
	}

      if (!args_info.quiet_given)
	fprintf (stderr, _("Session finished...\n"));

      if (!logout ())
	return 1;

      gsasl_finish (xctx);
    }

  if (sockfd)
    {
#ifdef HAVE_LIBGNUTLS
      if (using_tls)
	{
	  res = gnutls_bye (session, GNUTLS_SHUT_RDWR);
	  if (res < 0)
	    error (EXIT_FAILURE, 0,
		   _("terminating GnuTLS session failed: %s"),
		   gnutls_strerror (res));

	}
#endif
      shutdown (sockfd, SHUT_RDWR);
      close (sockfd);
    }

  gsasl_done (ctx);

#ifdef HAVE_LIBGNUTLS
  if (using_tls)
    {
      gnutls_deinit (session);
      gnutls_anon_free_client_credentials (anoncred);
      gnutls_certificate_free_credentials (x509cred);
      gnutls_global_deinit ();
    }
#endif

  return 0;
}
