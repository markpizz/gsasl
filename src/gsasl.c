/* gsasl.c	command line interface to libgsasl
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

enum
{
  OPTION_CLIENT_MECHANISMS = 300,
  OPTION_SERVER_MECHANISMS,
  OPTION_PASSCODE,
  OPTION_SERVICE,
  OPTION_HOSTNAME,
  OPTION_SERVICENAME,
  OPTION_ENABLE_CRAM_MD5_VALIDATE,
  OPTION_DISABLE_CLEARTEXT_VALIDATE,
  OPTION_QOP,
  OPTION_NO_CLIENT_FIRST,
  OPTION_IMAP,
  OPTION_CONNECT
};

const char *argp_program_version = "gsasl (" PACKAGE_STRING ")";
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

int mode;
int listmode;

int silent;
int verbose;
char *anonymous_token;
char *authentication_id;
char *authorization_id;
char *password;
char *passcode;
char *mechanism;
char *service;
char *hostname;
char *servicename;
char **realms;
size_t nrealms;
int enable_cram_md5_validate;
int disable_cleartext_validate;
size_t maxbuf;
int qop;
int application_data;
int no_client_first;
int imap;
char *connect_hostname;
char *connect_service;
struct sockaddr connect_addr;
int sockfd;
FILE *sockfh;

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'q':
      silent = 1;
      break;

    case 'v':
      verbose = 1;
      break;

    case 'a':
      authentication_id = strdup (arg);
      break;

    case 'z':
      authorization_id = strdup (arg);
      break;

    case 'p':
      password = strdup (arg);
      break;

    case 'n':
      anonymous_token = strdup (arg);
      break;

    case 'm':
      mechanism = strdup (arg);
      break;

    case 'r':
      if (nrealms == 0)
	realms = malloc (sizeof (*realms));
      else
	realms = realloc (realms, sizeof (*realms) * (nrealms + 1));
      if (realms == NULL)
	argp_error (state, gsasl_strerror (GSASL_MALLOC_ERROR));
      realms[nrealms++] = strdup (arg);
      break;

    case 'x':
      maxbuf = strtoul (arg, NULL, 0);
      break;

    case 'd':
      application_data = 1;
      break;

    case OPTION_PASSCODE:
      passcode = strdup (arg);
      break;

    case OPTION_SERVICE:
      service = strdup (arg);
      break;

    case OPTION_HOSTNAME:
      hostname = strdup (arg);
      break;

    case OPTION_SERVICENAME:
      servicename = strdup (arg);
      break;

    case OPTION_IMAP:
      imap = 1;
      if (!service)
	service = strdup ("imap");
      /* fall through */

    case OPTION_NO_CLIENT_FIRST:
      no_client_first = 1;
      break;

    case OPTION_ENABLE_CRAM_MD5_VALIDATE:
      enable_cram_md5_validate = 1;
      break;

    case OPTION_DISABLE_CLEARTEXT_VALIDATE:
      disable_cleartext_validate = 1;
      break;

    case OPTION_QOP:
      if (strcmp (arg, "auth") == 0)
	qop = GSASL_QOP_AUTH;
      else if (strcmp (arg, "auth-int") == 0)
	qop = GSASL_QOP_AUTH_INT;
      else if (strcmp (arg, "auth-conf") == 0)
	qop = GSASL_QOP_AUTH_CONF;
      else
	argp_error (state, "unknown quality of protection: `%s'", arg);
      break;

    case 'c':
    case 's':
      mode = key;
      break;

    case OPTION_CLIENT_MECHANISMS:
    case OPTION_SERVER_MECHANISMS:
      listmode = key;
      break;

    case OPTION_CONNECT:
      if (strrchr (arg, ':'))
	{
	  connect_hostname = strdup (arg);
	  *strrchr (connect_hostname, ':') = '\0';
	  connect_service = strdup (strrchr (arg, ':') + 1);
	}
      else
	{
	  connect_hostname = strdup (arg);
	  connect_service = strdup ("143");
	}
      {
	struct servent *se;
	struct hostent *he;
	struct sockaddr_in *sinaddr_inp =
	  (struct sockaddr_in *) &connect_addr;

	he = gethostbyname (connect_hostname);
	if (!he || he->h_addr_list[0] == NULL || he->h_addrtype != AF_INET)
	  argp_error (state, "unknown host: %s", connect_hostname);
	memset (&connect_addr, 0, sizeof (connect_addr));
	sinaddr_inp->sin_family = he->h_addrtype;
	memcpy (&sinaddr_inp->sin_addr, he->h_addr_list[0], he->h_length);
	se = getservbyname (connect_service, "tcp");
	if (se)
	  sinaddr_inp->sin_port = se->s_port;
	else
	  sinaddr_inp->sin_port = htons (atoi (connect_service));
	if (sinaddr_inp->sin_port == 0 || sinaddr_inp->sin_port == htons (0))
	  argp_error (state, "unknown service: %s", connect_service);

	sockfd = socket (AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	  {
	    perror ("socket()");
	    argp_error (state, "socket: %s", strerror (errno));
	  }

	if (connect (sockfd, &connect_addr, sizeof (connect_addr)) < 0)
	  {
	    perror ("connect()");
	    close (sockfd);
	    argp_error (state, "connect: %s", strerror (errno));
	  }
	sockfh = fdopen (sockfd, "r+");
	setvbuf (sockfh, NULL, _IONBF, 0);
      }
      if (!hostname)
	hostname = strdup (connect_hostname);
      break;

    case ARGP_KEY_ARG:
      argp_error (state, "too many arguments: `%s'", arg);
      break;

    case ARGP_KEY_END:
      if (mode == 0 && listmode == 0)
	{
	  argp_state_help (state, stdout, ARGP_HELP_STD_HELP);
	  exit (0);
	}
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp_option options[] = {

  {0, 0, 0, 0, "Commands:"},

  {"client", 'c', 0, 0, "Act as client."},

  {"server", 's', 0, 0, "Act as server."},

  {"client-mechanisms", OPTION_CLIENT_MECHANISMS, 0, 0,
   "Write name of supported client mechanisms separated by space to stdout."},

  {"server-mechanisms", OPTION_SERVER_MECHANISMS, 0, 0,
   "Write name of supported server mechanisms separated by space to stdout."},

  {0, 0, 0, 0, "Network parameters:", 100},

  {"connect", OPTION_CONNECT, "HOSTNAME[:SERVICE]", 0,
   "Connect to TCP server and negotiate on stream instead of stdin/stdout. "
   "SERVICE is the protocol service, or an integer denoting the port, "
   "and defaults to 143 (imap) if not specified. "
   "Also sets the --hostname default."},

  {0, 0, 0, 0, "Miscellaneous options:", 200},

  {"application-data", 'd', 0, 0,
   "After authentication, read data from stdin and run it through the "
   "mechanism's security layer and print it base64 encoded to stdout. "
   "The default is to terminate after authentication."},

  {"imap", OPTION_IMAP, 0, 0,
   "Use a IMAP-like logon procedure (client only). "
   "Also sets the --service default to \"imap\"."},

  {"mechanism", 'm', "STRING", 0,
   "Mechanism to use."},

  {"no-client-first", OPTION_NO_CLIENT_FIRST, 0, 0,
   "Disallow client to send data first (client only)."},

  {0, 0, 0, 0,
   "SASL mechanism options (prompted for if unspecified and needed):", 300},

  {"anonymous-token", 'n', "STRING", 0,
   "Token for anonymous authentication, usually mail address "
   "(ANONYMOUS only)."},

  {"authentication-id", 'a', "STRING", 0,
   "Identity of credential owner."},

  {"authorization-id", 'z', "STRING", 0,
   "Identity to request service for."},

  {"password", 'p', "STRING", 0,
   "Password for authentication (insecure for non-testing purposes)."},

  {"realm", 'r', "STRING", 0,
   "Realm (may be given more than once iff server). Defaults to hostname."},

  {"maxbuf", 'x', "NUMBER", 0,
   "Indicate maximum buffer size (DIGEST-MD5 only)."},

  {"passcode", OPTION_PASSCODE, "NUMBER", 0,
   "Passcode for authentication (SECURID only)."},

  {"service", OPTION_SERVICE, "STRING", 0,
   "Set the requested service name (should be a registered GSSAPI host "
   "based service name)."},

  {"hostname", OPTION_HOSTNAME, "STRING", 0,
   "Set the name of the server with the requested service."},

  {"service-name", OPTION_SERVICENAME, "STRING", 0,
   "Set the generic server name in case of a replicated server "
   "(DIGEST-MD5 only)."},

  {"enable-cram-md5-validate", OPTION_ENABLE_CRAM_MD5_VALIDATE, 0, 0,
   "Validate CRAM-MD5 challenge and response interactively."},

  {"disable-cleartext-validate", OPTION_DISABLE_CLEARTEXT_VALIDATE, 0, 0,
   "Disable cleartext validate hook, forcing server to prompt for password."},

  {"quality-of-protection", OPTION_QOP, "<auth | auth-int | auth-conf>", 0,
   "How application payload will be protected.  \"auth\" means no protection, "
   "\"auth-int\" means integrity protection, \"auth-conf\" means integrity "
   "and confidentialiy protection.  Currently only used by DIGEST-MD5, where "
   "the default is \"auth-conf\"."},

  {0, 0, 0, 0, "Other options:", 1000},

  {"verbose", 'v', 0, 0, "Produce verbose output."},

  {"quiet", 'q', 0, 0, "Don't produce any diagnostic output."},

  {"silent", 0, 0, OPTION_ALIAS},

  {0}
};

static struct argp argp = {
  options,
  parse_opt,
  0,
  "GNU SASL (gsasl) -- Command line interface to libgsasl."
};

static int
writeln (char *str)
{
  printf ("%s\n", str);

  if (sockfh)
    {
      int len;

      len = fprintf (sockfh, "%s\r\n", str);

      if (len != (int) strlen (str) + (int) strlen ("\r\n"))
	return 0;
    }

  return 1;
}

static int
readln (char *buf, size_t maxbuflen)
{
  if (!fgets (buf, maxbuflen, sockfh ? sockfh : stdin))
    return 0;

  while (buf[0] && (buf[strlen (buf) - 1] == '\n' ||
		    buf[strlen (buf) - 1] == '\r'))
    buf[strlen (buf) - 1] = '\0';

  if (sockfh)
    printf ("%s\n", buf);

  return 1;
}

int
main (int argc, char *argv[])
{
  Gsasl_ctx *ctx = NULL;
  int res;
  char input[MAX_LINE_LENGTH];

#ifdef HAVE_LOCALE_H
  setlocale (LC_ALL, "");
#endif
  bindtextdomain (PACKAGE, LOCALEDIR);

  argp_parse (&argp, argc, argv, 0, 0, NULL);

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fprintf (stderr, _("GSASL error (%d): %s\n"), res,
	       gsasl_strerror (res));
      return 1;
    }

  /* Set callbacks */
  if (maxbuf != 0)
    gsasl_client_callback_maxbuf_set (ctx, client_callback_maxbuf);
  if (qop != 0)
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
  if (maxbuf != 0)
    gsasl_server_callback_maxbuf_set (ctx, server_callback_maxbuf);
  if (enable_cram_md5_validate)
    gsasl_server_callback_cram_md5_set (ctx, server_callback_cram_md5);
  if (!disable_cleartext_validate)
    gsasl_server_callback_validate_set (ctx, server_callback_validate);
  gsasl_server_callback_retrieve_set (ctx, server_callback_retrieve);
  gsasl_server_callback_anonymous_set (ctx, server_callback_anonymous);
  gsasl_server_callback_external_set (ctx, server_callback_external);
  gsasl_server_callback_service_set (ctx, server_callback_service);
  gsasl_server_callback_gssapi_set (ctx, server_callback_gssapi);

  if (listmode == OPTION_CLIENT_MECHANISMS ||
      listmode == OPTION_SERVER_MECHANISMS)
    {
      char *mechs;

      if (listmode == OPTION_CLIENT_MECHANISMS)
	res = gsasl_client_mechlist (ctx, &mechs);
      else
	res = gsasl_server_mechlist (ctx, &mechs);

      if (res != GSASL_OK)
	{
	  fprintf (stderr, _("GSASL error (%d): %s\n"), res,
		   gsasl_strerror (res));
	  return 1;
	}

      if (!silent)
	fprintf (stderr, _("This %s supports the following mechanisms:\n"),
		 listmode == OPTION_CLIENT_MECHANISMS ?
		 _("client") : _("server"));

      fprintf (stdout, "%s\n", mechs);

      free (mechs);
    }

  if (imap && !readln (input, MAX_LINE_LENGTH))
    return 1;

  if (mode == 'c' || mode == 's')
    {
      char output[MAX_LINE_LENGTH];
      char b64output[MAX_LINE_LENGTH];
      size_t output_len;
      ssize_t b64output_len;
      const char *mech;
      Gsasl_session_ctx *xctx = NULL;
      int res;

      /* Decide mechanism to use */

      if (mode == 's')
	{
	  if (!silent)
	    fprintf (stderr, _("Chose SASL mechanisms:\n"));
	  if (!readln (input, MAX_LINE_LENGTH))
	    return 1;

	  if (!silent)
	    fprintf (stderr, _("Chosed mechanism `%s'\n"), input);
	  mech = input;
	}
      else			/* if (mode == 'c') */
	{
	  if (mechanism)
	    {
	      mech = mechanism;
	    }
	  else
	    {
	      if (imap && !writeln (". CAPABILITY"))
		return 1;

	      if (!silent && !imap)
		fprintf (stderr,
			 _("Input SASL mechanism supported by server:\n"));
	      if (!readln (input, MAX_LINE_LENGTH))
		return 1;

	      if (imap)
		/* XXX parse IMAP capability line */ ;

	      mech = gsasl_client_suggest_mechanism (ctx, input);
	      if (mech == NULL)
		{
		  fprintf (stderr, _("Cannot find mechanism...\n"));
		  return 1;
		}
	    }

	  if (imap)
	    {
	      sprintf (input, ". AUTHENTICATE %s", mech);
	      if (!writeln (input))
		return 1;
	    }
	  else
	    {
	      if (!silent)
		fprintf (stderr, _("Libgsasl wants to use:\n"));
	      puts (mech);
	    }
	}

      /* Authenticate using mechanism */

      if (mode == 'c')
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

      if (mode == 'c' && no_client_first)
	{
	  res = GSASL_NEEDS_MORE;
	  goto no_client_first;
	}

      do
	{
	  if (mode == 'c')
	    res = gsasl_client_step_base64 (xctx, input, output, output_len);
	  else
	    res = gsasl_server_step_base64 (xctx, input, output, output_len);

	  if (res != GSASL_NEEDS_MORE && res != GSASL_OK)
	    break;

	  if (imap)
	    {
	      sprintf (input, "+ %s", output);
	      if (!writeln (output))
		return 1;
	    }
	  else
	    {
	      if (!silent)
		{
		  if (mode == 'c')
		    fprintf (stderr, _("Output from client:\n"));
		  else
		    fprintf (stderr, _("Output from server:\n"));
		}
	      fprintf (stdout, "%s\n", output);
	    }

	  if (res != GSASL_NEEDS_MORE)
	    break;

	no_client_first:
	  if (!silent && !imap)
	    fprintf (stderr, _("Enter base64 authentication data from %s "
			       "(press RET if none):\n"),
		     mode == 'c' ? _("server") : _("client"));

	  if (!readln (input, MAX_LINE_LENGTH))
	    return 1;

	  if (imap)
	    {
	      if (input[0] != '+' || input[1] != ' ')
		{
		  fprintf (stderr,
			   _("error: Server did not return expected SASL "
			     "data (it must begin with '+ '):\n%s\n"), input);
		  return 1;
		}
	      strcpy (&input[0], &input[2]);
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
      if (imap && !readln (input, MAX_LINE_LENGTH))
	return 1;

      if (!silent)
	{
	  if (mode == 'c')
	    fprintf (stderr, _("Client authentication "
			       "finished (server trusted)...\n"));
	  else
	    fprintf (stderr, _("Server authentication "
			       "finished (client trusted)...\n"));
	}

      if (imap)
	/* XXX check server outcome (NO vs OK vs still waiting) */ ;

      /* Transfer application payload */
      if (application_data)
	{
	  fd_set readfds;

	  FD_ZERO (&readfds);
	  FD_SET (STDIN_FILENO, &readfds);
	  if (sockfh)
	    FD_SET (sockfd, &readfds);

	  if (!silent)
	    fprintf (stderr, _("Enter application data (EOF to finish):\n"));

	  while (select (sockfd + 1, &readfds, NULL, NULL, NULL))
	    {
	      if (FD_ISSET (STDIN_FILENO, &readfds))
		{
		  input[0] = '\0';
		  if (fgets (input, MAX_LINE_LENGTH - 2, stdin) == NULL)
		    break;
		  if (imap)
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

		      if (!silent)
			fprintf (stderr, _("Base64 encoded application "
					   "data to send:\n"));
		      fprintf (stdout, "%s\n", b64output);
		    }

		  if (sockfh)
		    {
		      if (fwrite (output, sizeof (output[0]),
				  output_len, sockfh) != output_len)
			return 0;
		    }
		}

	      if (sockfd && FD_ISSET (sockfd, &readfds))
		{
		  input[0] = '\0';
		  if (fgets (input, MAX_LINE_LENGTH, sockfh) == NULL)
		    break;
		  input[strlen (input) - 1] = '\0';
		  printf ("%s\n", input);
		}

	      FD_ZERO (&readfds);
	      FD_SET (STDIN_FILENO, &readfds);
	      if (sockfh)
		FD_SET (sockfd, &readfds);
	    }

	  if (res != GSASL_OK)
	    {
	      fprintf (stderr, _("Libgsasl error (%d): %s\n"),
		       res, gsasl_strerror (res));
	      return 1;
	    }
	}

      if (!silent)
	{
	  if (mode == 'c')
	    fprintf (stderr, _("Client finished...\n"));
	  else
	    fprintf (stderr, _("Server finished...\n"));
	}

      if (mode == 'c')
	gsasl_client_finish (xctx);
      else
	gsasl_server_finish (xctx);
    }

  if (imap && !writeln (". LOGOUT"))
    return 1;

  if (sockfh)
    {
      /* read "* BYE ..." */
      if (!readln (input, MAX_LINE_LENGTH))
	return 1;

      /* read ". OK ..." */
      if (!readln (input, MAX_LINE_LENGTH))
	return 1;

      shutdown (sockfd, SHUT_RDWR);
      fclose (sockfh);
    }

  gsasl_done (ctx);

  return 0;
}
