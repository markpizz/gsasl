/* gsasl-saml20-request.c --- Generate SAML Request, for smtp-server-saml20.
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

#include <config.h>

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdio.h>
#include <lasso/lasso.h>
#include <lasso/xml/saml-2.0/samlp2_authn_request.h>

static void
mkdir_state (const char *state_path)
{
  int rc;

  rc = mkdir (state_path, 0770);
  if (rc != 0 && errno != EEXIST)
    {
      perror ("mkdir");
      exit (EXIT_FAILURE);
    }
}

static void
mkdir_session (const char *state_path, const char *id)
{
  char *tmp;
  int rc;

  rc = asprintf (&tmp, "%s/%s", state_path, id);
  if (rc <= 0)
    {
      perror ("asprintf");
      exit (EXIT_FAILURE);
    }

  rc = mkdir (tmp, 0770);
  free (tmp);
  if (rc != 0)
    {
      perror ("mkdir");
      exit (EXIT_FAILURE);
    }
}

static void
write_file (const char *file, const char *data)
{
  FILE *fh;

  fh = fopen (file, "w");
  if (!fh)
    {
      perror ("fopen");
      exit (EXIT_FAILURE);
    }

  if (fprintf (fh, "%s", data) <= 0)
    {
      perror ("fprintf");
      exit (EXIT_FAILURE);
    }

  if (fclose (fh))
    {
      perror ("fclose");
      exit (EXIT_FAILURE);
    }
}

static void
write_authreq (LassoLogin * login, const char *state_path, const char *id)
{
  LassoNode *authreq;
  char *authreq_xml;
  char *filename;
  int rc;

  authreq = LASSO_PROFILE (login)->request;
  if (!authreq)
    {
      fprintf (stderr, "LASSO_PROFILE(login)->request\n");
      exit (EXIT_FAILURE);
    }

  authreq_xml = lasso_node_export_to_xml (authreq);
  if (!authreq_xml)
    {
      fprintf (stderr, "lasso_node_export_to_xml\n");
      exit (EXIT_FAILURE);
    }

  rc = asprintf (&filename, "%s/%s/saml-request", state_path, id);
  if (rc <= 0)
    {
      perror ("asprintf");
      free (authreq_xml);
      exit (EXIT_FAILURE);
    }

  write_file (filename, authreq_xml);

  free (filename);
  free (authreq_xml);
}

static void
write_redirect_url (LassoLogin * login, const char *state_path,
		    const char *id)
{
  char *filename;
  int rc;

  rc = asprintf (&filename, "%s/%s/redirect_url", state_path, id);
  if (rc <= 0)
    {
      perror ("asprintf");
      exit (EXIT_FAILURE);
    }

  write_file (filename, LASSO_PROFILE (login)->msg_url);

  free (filename);
}

static void
usage (const char *argv0)
{
  const char *progname = strrchr (argv0, '/') ?
    1 + strrchr (argv0, '/') : argv0;

  fprintf (stderr, "Usage: %s STATE-PATH SP-METADATA SP-KEY "
	   "SP-CRT IDP-METADATA\n", progname);
  fprintf (stderr, "For example:\n");
  fprintf (stderr, "   %s /tmp/gsasl-saml20 /path/to/sp-metadata.xml "
	   "/path/to/sp-key.pem /path/to/sp-crt.pem "
	   "/path/to/idp-metadata.xml\n", progname);
}

int
main (int argc, char *argv[])
{
  const char *state_path, *spmetadata, *spkey, *spcrt, *idpmetadata, *idp;
  LassoProvider *provider;
  LassoServer *server;
  LassoLogin *login;
  LassoSamlp2AuthnRequest *request;
  int rc;

  if (argc != 6)
    {
      usage (argv[0]);
      exit (EXIT_FAILURE);
    }

  state_path = argv[1];
  spmetadata = argv[2];
  spkey = argv[3];
  spcrt = argv[4];
  idpmetadata = argv[5];

  mkdir_state (state_path);

  rc = lasso_init ();
  if (rc)
    {
      fprintf (stderr, "lasso_init (%d): %s\n", rc, lasso_strerror (rc));
      exit (EXIT_FAILURE);
    }

  provider = lasso_provider_new (LASSO_PROVIDER_ROLE_IDP,
				 idpmetadata, NULL, NULL);
  if (!provider)
    {
      fprintf (stderr, "%s", "lasso_provider_new");
      exit (EXIT_FAILURE);
    }

  idp = provider->ProviderID;

  server = lasso_server_new (spmetadata, spkey, NULL, spcrt);
  if (!server)
    {
      fprintf (stderr, "%s", "lasso_server_new");
      exit (EXIT_FAILURE);
    }

  rc = lasso_server_add_provider (server, LASSO_PROVIDER_ROLE_IDP,
				  idpmetadata, NULL, NULL);
  if (rc)
    {
      fprintf (stderr, "lasso_server_add_provider (%d): %s\n",
	       rc, lasso_strerror (rc));
      exit (EXIT_FAILURE);
    }

  login = lasso_login_new (server);
  if (!login)
    {
      fprintf (stderr, "%s", "lasso_login_new");
      exit (EXIT_FAILURE);
    }

  rc = lasso_login_init_authn_request (login, idp,
				       LASSO_HTTP_METHOD_REDIRECT);
  if (rc)
    {
      fprintf (stderr, "lasso_login_init_authn_request (%d): %s\n",
	       rc, lasso_strerror (rc));
      exit (EXIT_FAILURE);
    }

  request = LASSO_SAMLP2_AUTHN_REQUEST (LASSO_PROFILE (login)->request);

  request->ForceAuthn = FALSE;
  request->IsPassive = FALSE;

  rc = lasso_login_build_authn_request_msg (login);
  if (rc)
    {
      fprintf (stderr, "lasso_login_build_authn_request_msg (%d): %s\n",
	       rc, lasso_strerror (rc));
      exit (EXIT_FAILURE);
    }

  /* Populate session directory. */
  mkdir_session (state_path, request->parent.ID);
  write_authreq (login, state_path, request->parent.ID);
  write_redirect_url (login, state_path, request->parent.ID);

  /* Print session ID, this will enable the caller to find the session
     information. */
  if (puts (request->parent.ID) <= 0)
    {
      perror ("puts");
      exit (EXIT_FAILURE);
    }

  /* We are done. */
  lasso_login_destroy (login);
  lasso_server_destroy (server);
  /* lasso_provider_destroy (provider); */
  rc = lasso_shutdown ();
  if (rc)
    {
      fprintf (stderr, "lasso_shutdown (%d): %s\n", rc, lasso_strerror (rc));
      exit (EXIT_FAILURE);
    }

  exit (EXIT_SUCCESS);
}
