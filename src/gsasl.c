/* gsasl.c --- Command line interface to libgsasl.
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
#include "gsasl_cmd.h"

struct gengetopt_args_info args_info;
int sockfd;

static int
writeln (char *str)
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

static int
readln (char *buf, size_t maxbuflen)
{
  if (sockfd)
    {
      ssize_t len;
      len = recv (sockfd, buf, maxbuflen, 0);
      if (len <= 0)
	return 0;
      buf[len] = '\0';
    }
  else if (!fgets (buf, maxbuflen, stdin))
    return 0;

  if (sockfd)
    printf ("%s", buf);

  return 1;
}

#define MAX_LINE_LENGTH BUFSIZ

static int
readln1 (char **out)
{
  char input[MAX_LINE_LENGTH];

  if (sockfd)
    {
      ssize_t len;
      len = recv (sockfd, input, MAX_LINE_LENGTH, 0);
      if (len <= 0)
	return 0;
      input[len] = '\0';
    }
  else if (!fgets (input, MAX_LINE_LENGTH, stdin))
    return 0;

  if (sockfd)
    printf ("%s", input);

  *out = strdup (input);

  return 1;
}

int
greeting (void)
{
  char *in;

  if (args_info.imap_flag && !readln1 (&in))
    return 0;

  return 1;
}

int
logout (void)
{
  char *in;

  if (args_info.imap_flag)
    {
      if (!writeln (". LOGOUT"))
	return 1;

      /* read "* BYE ..." */
      if (!readln1 (&in))
	return 1;

      free (in);

      /* read ". OK ..." */
      if (!readln1 (&in))
	return 1;

      free (in);
    }

  return 0;
}

int
main (int argc, char *argv[])
{
  Gsasl_ctx *ctx = NULL;
  int res;
  char input[MAX_LINE_LENGTH];
  char *connect_hostname;
  char *connect_service;
  struct sockaddr connect_addr;

#ifdef HAVE_LOCALE_H
  setlocale (LC_ALL, "");
#endif
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  if (cmdline_parser (argc, argv, &args_info) != 0)
    return 1;

  if (!args_info.client_flag &&
      !args_info.server_flag &&
      !args_info.client_mechanisms_flag &&
      !args_info.server_mechanisms_flag)
    {
      fprintf (stderr, "%s: missing argument\n", argv[0]);
      cmdline_parser_print_help ();
      printf ("\nReport bugs to <%s>\n", PACKAGE_BUGREPORT);
      return 1;
    }

  if (args_info.imap_flag && !args_info.service_given)
    {
      args_info.service_arg = strdup ("imap");
      args_info.no_client_first_flag = 1;
    }

  if (args_info.connect_given)
    {
      struct servent *se;
      struct hostent *he;
      struct sockaddr_in *sinaddr_inp =
	(struct sockaddr_in *) &connect_addr;

      if (strrchr (args_info.connect_arg, ':'))
	{
	  connect_hostname = strdup (args_info.connect_arg);
	  *strrchr (connect_hostname, ':') = '\0';
	  connect_service = strdup (strrchr (args_info.connect_arg, ':') + 1);
	}
      else
	{
	  connect_hostname = strdup (args_info.connect_arg);
	  connect_service = strdup ("143");
	}

      he = gethostbyname (connect_hostname);
      if (!he || he->h_addr_list[0] == NULL || he->h_addrtype != AF_INET)
	{
	  fprintf (stderr, "%s: unknown host: %s", argv[0],
		   connect_hostname);
	  return 1;
	}
      memset (&connect_addr, 0, sizeof (connect_addr));
      sinaddr_inp->sin_family = he->h_addrtype;
      memcpy (&sinaddr_inp->sin_addr, he->h_addr_list[0], he->h_length);
      se = getservbyname (connect_service, "tcp");
      if (se)
	sinaddr_inp->sin_port = se->s_port;
      else
	sinaddr_inp->sin_port = htons (atoi (connect_service));
      if (sinaddr_inp->sin_port == 0 || sinaddr_inp->sin_port == htons (0))
	{
	  fprintf (stderr, "%s: unknown service: %s", argv[0],
		   connect_service);
	  return 1;
	}

      sockfd = socket (AF_INET, SOCK_STREAM, 0);
      if (sockfd < 0)
	{
	  perror ("socket()");
	  fprintf (stderr, "%s: socket: %s", argv[0], strerror (errno));
	  return 1;
	}

      if (connect (sockfd, &connect_addr, sizeof (connect_addr)) < 0)
	{
	  perror ("connect()");
	  close (sockfd);
	  fprintf (stderr, "%s: connect: %s", argv[0], strerror (errno));
	  return 1;
	}
      if (!args_info.hostname_arg)
	args_info.hostname_arg = strdup (connect_hostname);
    }

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fprintf (stderr, _("GSASL error (%d): %s\n"), res,
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
	  fprintf (stderr, _("GSASL error (%d): %s\n"), res,
		   gsasl_strerror (res));
	  return 1;
	}

      if (!args_info.quiet_given)
	fprintf (stderr, _("This %s supports the following mechanisms:\n"),
		 args_info.client_mechanisms_flag ? _("client") : _("server"));

      fprintf (stdout, "%s\n", mechs);

      free (mechs);
    }

  if (args_info.client_flag || args_info.server_flag)
    {
      char output[MAX_LINE_LENGTH];
      char b64output[MAX_LINE_LENGTH];
      size_t output_len;
      ssize_t b64output_len;
      const char *mech;
      Gsasl_session_ctx *xctx = NULL;
      int res;

      if (!greeting ())
	return 1;

      /* Decide mechanism to use */

      if (args_info.mechanism_arg)
	{
	  mech = args_info.mechanism_arg;
	}
      else if (args_info.server_flag)
	{
	  if (!args_info.quiet_given)
	    fprintf (stderr, _("Chose SASL mechanisms:\n"));
	  if (!readln (input, MAX_LINE_LENGTH))
	    return 1;
	  mech = input;
	}
      else /* if (args_info.client_flag) */
	{
	  if (args_info.imap_flag && !writeln (". CAPABILITY"))
	    return 1;

	  if (!args_info.quiet_given && !args_info.imap_flag)
	    fprintf (stderr,
		     _("Input SASL mechanism supported by server:\n"));
	  if (!readln (input, MAX_LINE_LENGTH))
	    return 1;

	  if (args_info.imap_flag)
	    /* XXX parse IMAP capability line */ ;

	  mech = gsasl_client_suggest_mechanism (ctx, input);
	  if (mech == NULL)
	    {
	      fprintf (stderr, _("Cannot find mechanism...\n"));
	      return 1;
	    }
	}

      if (args_info.imap_flag && args_info.client_flag)
	{
	  sprintf (input, ". AUTHENTICATE %s", mech);
	  if (!writeln (input))
	    return 1;
	}
      else
	{
	  if (!args_info.quiet_given)
	    fprintf (stderr, _("Using mechanism:\n"));
	  puts (mech);
	}

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

      input[0] = '\0';
      output[0] = '\0';
      output_len = sizeof (output);

      if (args_info.client_flag && args_info.no_client_first_flag)
	{
	  res = GSASL_NEEDS_MORE;
	  goto no_client_first;
	}

      do
	{
	  if (args_info.client_flag)
	    res = gsasl_client_step_base64 (xctx, input, output, output_len);
	  else
	    res = gsasl_server_step_base64 (xctx, input, output, output_len);

	  if (res != GSASL_NEEDS_MORE && res != GSASL_OK)
	    break;

	  if (args_info.imap_flag)
	    {
	      if (args_info.client_flag)
		sprintf (input, "%s", output);
	      else
		sprintf (input, "+ %s", output);
	      if (!writeln (input))
		return 1;
	    }
	  else
	    {
	      if (!args_info.quiet_given)
		{
		  if (args_info.client_flag)
		    fprintf (stderr, _("Output from client:\n"));
		  else
		    fprintf (stderr, _("Output from server:\n"));
		}
	      fprintf (stdout, "%s\n", output);
	    }

	  if (res != GSASL_NEEDS_MORE)
	    break;

	no_client_first:
	  if (!args_info.quiet_given && !args_info.imap_flag)
	    fprintf (stderr, _("Enter base64 authentication data from %s "
			       "(press RET if none):\n"),
		     args_info.client_flag ? _("server") : _("client"));

	  if (!readln (input, MAX_LINE_LENGTH))
	    return 1;

	  if (args_info.imap_flag)
	    {
	      if (input[0] != '+' || input[1] != ' ')
		{
		  fprintf (stderr,
			   _("error: Server did not return expected SASL "
			     "data (it must begin with '+ '):\n%s\n"), input);
		  return 1;
		}
	      memmove (&input[0], &input[2], strlen (input) - 1);
	    }
	}
      while (res == GSASL_NEEDS_MORE);

      if (res != GSASL_OK)
	{
	  fprintf (stderr, _("Libgsasl error (%d): %s\n"),
		   res, gsasl_strerror (res));
	  return 1;
	}

      /* wait for possibly last round trip */
      if (args_info.imap_flag && !readln (input, MAX_LINE_LENGTH))
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

      if (args_info.imap_flag)
	/* XXX check server outcome (NO vs OK vs still waiting) */ ;

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
		  if (args_info.imap_flag)
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
		if (!readln (input, MAX_LINE_LENGTH))
		  break;

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

      gsasl_finish (xctx);
    }

  if (!logout ())
    return 1;

  if (sockfd)
    {
      shutdown (sockfd, SHUT_RDWR);
      close (sockfd);
    }

  gsasl_done (ctx);

  return 0;
}
