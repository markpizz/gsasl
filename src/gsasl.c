/* gsasl.c --- Command line interface to libgsasl.
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

#include <progname.h>

#include "internal.h"
#include "callbacks.h"
#include "imap.h"
#include "smtp.h"

#define MAX_LINE_LENGTH BUFSIZ

struct gengetopt_args_info args_info;
int sockfd;

int
writeln (const char *str)
{
  printf ("%s\n", str);

  if (sockfd)
    {
      size_t len;

      len = write (sockfd, str, strlen (str));
      if (len != strlen (str))
	return 0;

      len = write (sockfd, "\r\n", strlen ("\r\n"));
      if (len != strlen ("\r\n"))
	return 0;
    }

  return 1;
}

int
readln (char **out)
{
  char input[MAX_LINE_LENGTH];

  if (sockfd)
    {
      ssize_t len;
      size_t j = 0;

      /* FIXME: Optimize and remove size limit. */

      do
	{
	  j++;
	  len = recv (sockfd, &input[j - 1], 1, 0);
	  if (len <= 0)
	    return 0;
	}
      while (input[j - 1] != '\n' && j < MAX_LINE_LENGTH);
      input[j] = '\0';
    }
  else
    {
      /* FIXME: Use readline?  Or getline. */

      if (!fgets (input, MAX_LINE_LENGTH, stdin))
	return 0;
    }

  if (sockfd)
    printf ("%s", input);

  *out = strdup (input);

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
	fprintf (stderr, _("Chose SASL mechanism:\n"));
      if (!readln (&in))
	return 0;
      *mechlist = in;
    }
  else				/* if (args_info.client_flag) */
    {
      if (!args_info.quiet_given)
	fprintf (stderr, _("Input SASL mechanism supported by server:\n"));
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
      if (args_info.client_flag)
	fprintf (stderr, _("Output from client:\n"));
      else
	fprintf (stderr, _("Output from server:\n"));
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

int
main (int argc, char *argv[])
{
  Gsasl_ctx *ctx = NULL;
  int res;
  char input[MAX_LINE_LENGTH];
  char *in;

  set_program_name (argv[0]);
#ifdef HAVE_LOCALE_H
  setlocale (LC_ALL, "");
#endif
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  if (cmdline_parser (argc, argv, &args_info) != 0)
    return 1;

  if (!args_info.client_flag &&
      !args_info.server_flag &&
      !args_info.client_mechanisms_flag && !args_info.server_mechanisms_flag)
    {
      fprintf (stderr, "%s: missing argument\n", argv[0]);
      cmdline_parser_print_help ();
      printf ("\nReport bugs to <%s>\n", PACKAGE_BUGREPORT);
      return 1;
    }

  if (args_info.smtp_flag && args_info.imap_flag)
    args_info.imap_flag = 0;

  if (args_info.imap_flag && !args_info.service_given)
    {
      args_info.service_arg = strdup ("imap");
      args_info.no_client_first_flag = 1;
    }

  if (args_info.smtp_flag && !args_info.service_given)
    {
      args_info.service_arg = strdup ("smtp");
      args_info.no_client_first_flag = 1;
    }

  if (args_info.connect_given || args_info.inputs_num > 0)
    {
      char *connect_hostname;
      char *connect_service;
      struct sockaddr connect_addr;
      struct sockaddr *saddr = &connect_addr;
      size_t saddrlen = sizeof (*saddr);
#if HAVE_GETADDRINFO
      struct addrinfo hints;
      struct addrinfo *ai;
      int gairc;
#else
      struct servent *se;
      struct hostent *he;
#endif

      if (args_info.connect_given)
	{
	  if (strrchr (args_info.connect_arg, ':'))
	    {
	      connect_hostname = strdup (args_info.connect_arg);
	      *strrchr (connect_hostname, ':') = '\0';
	      connect_service =
		strdup (strrchr (args_info.connect_arg, ':') + 1);
	    }
	  else
	    {
	      connect_hostname = strdup (args_info.connect_arg);
	      if (args_info.smtp_flag)
		connect_service = strdup ("25");
	      else
		connect_service = strdup ("143");
	    }
	}
      else if (args_info.inputs_num > 0)
	{
	  connect_hostname = args_info.inputs[0];
	  if (args_info.inputs_num > 1)
	    connect_service = args_info.inputs[1];
	  else if (args_info.smtp_flag)
	    connect_service = strdup ("25");
	  else
	    connect_service = strdup ("143");
	}

#if HAVE_GETADDRINFO
      memset (&hints, 0, sizeof (hints));
      hints.ai_socktype = SOCK_STREAM;
      gairc = getaddrinfo (connect_hostname, connect_service, &hints, &ai);
      if (gairc != 0)
	{
	  fprintf (stderr, "%s: getaddrinfo (%s, %s): %s\n", argv[0],
		   connect_hostname, connect_service, gai_strerror(gairc));
	  return 1;
	}
      saddr = ai->ai_addr;
      saddrlen = ai->ai_addrlen;
#else
      memset (&connect_addr, 0, sizeof (connect_addr));
      he = gethostbyname (connect_hostname);
      if (!he || he->h_addr_list[0] == NULL)
	{
	  fprintf (stderr, "%s: unknown host: %s\n", argv[0],
		   connect_hostname);
	  return 1;
	}
      saddr->sa_family = he->h_addrtype;
      if (he->h_addrtype == AF_INET)
	{
	  struct sockaddr_in *saddrin = (struct sockaddr_in *) &connect_addr;
	  memcpy (&saddrin->sin_addr, he->h_addr_list[0], he->h_length);
	  se = getservbyname (connect_service, "tcp");
	  if (se)
	    saddrin->sin_port = se->s_port;
	  else if (atoi (connect_service) == 0)
	    {
	      fprintf (stderr, "%s: unknown service: %s\n", argv[0],
		       connect_service);
	      return 1;
	    }
	  else
	    saddrin->sin_port = htons (atoi (connect_service));
	}
      else
	{
	  fprintf (stderr, "%s: unsupported address type: %d\n",
		   argv[0], he->h_addrtype);
	  return 1;
	}
#endif

      sockfd = socket (saddr->sa_family, SOCK_STREAM, 0);
      if (sockfd < 0)
	{
	  fprintf (stderr, "%s: ", argv[0]);
	  perror ("socket");
	  return 1;
	}

      if (connect (sockfd, saddr, saddrlen) < 0)
	{
	  fprintf (stderr, "%s: ", argv[0]);
	  perror ("connect");
	  close (sockfd);
	  return 1;
	}

#if HAVE_GETADDRINFO
      freeaddrinfo (ai);
#endif

      if (!args_info.hostname_arg)
	args_info.hostname_arg = strdup (connect_hostname);
    }

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fprintf (stderr, _("Libgsasl error (%d): %s\n"), res,
	       gsasl_strerror (res));
      return 1;
    }

  /* Set callbacks */
  if (args_info.maxbuf_arg != 0)
    gsasl_client_callback_maxbuf_set (ctx, client_callback_maxbuf);
  if (args_info.quality_of_protection_arg != 0)
    gsasl_client_callback_qop_set (ctx, client_callback_qop);
  gsasl_client_callback_anonymous_set (ctx, client_callback_anonymous);
  gsasl_client_callback_authentication_id_set
    (ctx, client_callback_authentication_id);
  gsasl_client_callback_authorization_id_set
    (ctx, client_callback_authorization_id);
  gsasl_client_callback_password_set (ctx, client_callback_password);
  gsasl_client_callback_passcode_set (ctx, client_callback_passcode);
  gsasl_client_callback_service_set (ctx, client_callback_service);
  gsasl_client_callback_realm_set (ctx, client_callback_realm);

  gsasl_server_callback_realm_set (ctx, server_callback_realm);
  gsasl_server_callback_qop_set (ctx, server_callback_qop);
  if (args_info.maxbuf_arg != 0)
    gsasl_server_callback_maxbuf_set (ctx, server_callback_maxbuf);
  if (args_info.enable_cram_md5_validate_flag)
    gsasl_server_callback_cram_md5_set (ctx, server_callback_cram_md5);
  if (!args_info.disable_cleartext_validate_flag)
    gsasl_server_callback_validate_set (ctx, server_callback_validate);
  gsasl_server_callback_retrieve_set (ctx, server_callback_retrieve);
  gsasl_server_callback_anonymous_set (ctx, server_callback_anonymous);
  gsasl_server_callback_external_set (ctx, server_callback_external);
  gsasl_server_callback_service_set (ctx, server_callback_service);
  gsasl_server_callback_gssapi_set (ctx, server_callback_gssapi);

  if (args_info.client_mechanisms_flag || args_info.server_mechanisms_flag)
    {
      char *mechs;

      if (args_info.client_mechanisms_flag)
	res = gsasl_client_mechlist (ctx, &mechs);
      else
	res = gsasl_server_mechlist (ctx, &mechs);

      if (res != GSASL_OK)
	{
	  fprintf (stderr, _("Libgsasl error (%d): %s\n"), res,
		   gsasl_strerror (res));
	  return 1;
	}

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
    }

  if (args_info.client_flag || args_info.server_flag)
    {
      char output[MAX_LINE_LENGTH];
      char *out;
      char b64output[MAX_LINE_LENGTH];
      size_t output_len;
      ssize_t b64output_len;
      const char *mech;
      Gsasl_session_ctx *xctx = NULL;

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

      if (args_info.client_flag)
	res = gsasl_client_start (ctx, mech, &xctx);
      else
	res = gsasl_server_start (ctx, mech, &xctx);
      if (res != GSASL_OK)
	{
	  fprintf (stderr, _("Libgsasl error (%d): %s\n"),
		   res, gsasl_strerror (res));
	  return 1;
	}

      in = NULL;
      out = NULL;

      if (args_info.client_flag && args_info.no_client_first_flag)
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
	      if (args_info.client_flag)
		fprintf (stderr, _("Enter base64 authentication data "
				   "from server (press RET if none):\n"));
	      else
		fprintf (stderr, _("Enter base64 authentication data "
				   "from client (press RET if none):\n"));
	    }

	  if (!step_recv (&in))
	    return 1;
	}
      while (res == GSASL_NEEDS_MORE);

      if (res != GSASL_OK)
	{
	  fprintf (stderr, _("Libgsasl error (%d): %s\n"),
		   res, gsasl_strerror (res));
	  return 1;
	}

      if (!auth_finish ())
	return 1;

      if (!args_info.quiet_given)
	{
	  if (args_info.client_flag)
	    fprintf (stderr, _("Client authentication "
			       "finished (server trusted)...\n"));
	  else
	    fprintf (stderr, _("Server authentication "
			       "finished (client trusted)...\n"));
	}

      /* Transfer application payload */
      if (args_info.application_data_flag)
	{
	  fd_set readfds;

	  FD_ZERO (&readfds);
	  FD_SET (STDIN_FILENO, &readfds);
	  if (sockfd)
	    FD_SET (sockfd, &readfds);

	  if (!args_info.quiet_given)
	    fprintf (stderr, _("Enter application data (EOF to finish):\n"));

	  while (select (sockfd + 1, &readfds, NULL, NULL, NULL))
	    {
	      if (FD_ISSET (STDIN_FILENO, &readfds))
		{
		  input[0] = '\0';
		  if (fgets (input, MAX_LINE_LENGTH - 2, stdin) == NULL)
		    break;
		  if (args_info.imap_flag || args_info.smtp_flag)
		    {
		      int pos = strlen (input);
		      input[pos - 1] = '\r';
		      input[pos] = '\n';
		      input[pos + 1] = '\0';
		    }
		  else
		    input[strlen (input) - 1] = '\0';

		  output_len = sizeof (output);
		  res = gsasl_encode (xctx, input, strlen (input),
				      output, &output_len);
		  if (res != GSASL_OK)
		    break;

		  if (!(strlen (input) == output_len &&
			memcmp (input, output, output_len) == 0))
		    {
		      b64output_len = sizeof (b64output);
		      b64output_len = gsasl_base64_encode (output, output_len,
							   b64output,
							   b64output_len);
		      if (b64output_len == -1)
			{
			  res = GSASL_BASE64_ERROR;
			  break;
			}

		      if (!args_info.quiet_given)
			fprintf (stderr, _("Base64 encoded application "
					   "data to send:\n"));
		      fprintf (stdout, "%s\n", b64output);
		    }

		  if (sockfd)
		    {
		      if (write (sockfd, output, output_len) != output_len)
			return 0;
		    }
		}

	      if (sockfd && FD_ISSET (sockfd, &readfds))
		{
		  if (!readln (&in))
		    break;
		  free (in);
		}

	      FD_ZERO (&readfds);
	      FD_SET (STDIN_FILENO, &readfds);
	      if (sockfd)
		FD_SET (sockfd, &readfds);
	    }

	  if (res != GSASL_OK)
	    {
	      fprintf (stderr, _("Libgsasl error (%d): %s\n"),
		       res, gsasl_strerror (res));
	      return 1;
	    }
	}

      if (!args_info.quiet_given)
	fprintf (stderr, _("Session finished...\n"));

      if (!logout ())
	return 1;

      gsasl_finish (xctx);
    }

  if (sockfd)
    {
      shutdown (sockfd, SHUT_RDWR);
      close (sockfd);
    }

  gsasl_done (ctx);

  return 0;
}
