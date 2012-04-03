/* client.c --- SASL SCRAM client side functions.
 * Copyright (C) 2009-2012 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Get specification. */
#include "scram.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen, strchr. */
#include <string.h>

/* Get bool. */
#include <stdbool.h>

#include "tokens.h"
#include "parser.h"
#include "printer.h"
#include "gc.h"
#include "memxor.h"

#define CNONCE_ENTROPY_BYTES 18

struct scram_client_state
{
  int plus;
  int step;
  char *cfmb;			/* client first message bare */
  char *serversignature;
  char *authmessage;
  char *cbtlsunique;
  size_t cbtlsuniquelen;
  struct scram_client_first cf;
  struct scram_server_first sf;
  struct scram_client_final cl;
  struct scram_server_final sl;
};

static int
scram_start (Gsasl_session * sctx, void **mech_data, int plus)
{
  struct scram_client_state *state;
  char buf[CNONCE_ENTROPY_BYTES];
  const char *p;
  int rc;

  state = (struct scram_client_state *) calloc (sizeof (*state), 1);
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->plus = plus;

  rc = gsasl_nonce (buf, CNONCE_ENTROPY_BYTES);
  if (rc != GSASL_OK)
    {
      free (state);
      return rc;
    }

  rc = gsasl_base64_to (buf, CNONCE_ENTROPY_BYTES,
			&state->cf.client_nonce, NULL);
  if (rc != GSASL_OK)
    {
      free (state);
      return rc;
    }

  p = gsasl_property_get (sctx, GSASL_CB_TLS_UNIQUE);
  if (state->plus && !p)
    {
      free (state->cf.client_nonce);
      free (state);
      return GSASL_NO_CB_TLS_UNIQUE;
    }
  if (p)
    {
      rc = gsasl_base64_from (p, strlen (p), &state->cbtlsunique,
			      &state->cbtlsuniquelen);
      if (rc != GSASL_OK)
	{
	  free (state->cf.client_nonce);
	  free (state);
	  return rc;
	}
    }

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_scram_sha1_client_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, 0);
}

int
_gsasl_scram_sha1_plus_client_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, 1);
}

static char
hexdigit_to_char (char hexdigit)
{
  if (hexdigit >= '0' && hexdigit <= '9')
    return hexdigit - '0';
  if (hexdigit >= 'a' && hexdigit <= 'f')
    return hexdigit - 'a' + 10;
  return 0;
}

static char
hex_to_char (char u, char l)
{
  return (char) (((unsigned char) hexdigit_to_char (u)) * 16
		 + hexdigit_to_char (l));
}

static void
sha1_hex_to_byte (char *saltedpassword, const char *p)
{
  while (*p)
    {
      *saltedpassword = hex_to_char (p[0], p[1]);
      p += 2;
      saltedpassword++;
    }
}

static bool
hex_p (const char *hexstr)
{
  static const char hexalpha[] = "0123456789abcdef";

  for (; *hexstr; hexstr++)
    if (strchr (hexalpha, *hexstr) == NULL)
      return false;

  return true;
}

int
_gsasl_scram_sha1_client_step (Gsasl_session * sctx,
			       void *mech_data,
			       const char *input, size_t input_len,
			       char **output, size_t * output_len)
{
  struct scram_client_state *state = mech_data;
  int res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
  int rc;

  *output = NULL;
  *output_len = 0;

  switch (state->step)
    {
    case 0:
      {
	const char *p;

	if (state->plus)
	  {
	    state->cf.cbflag = 'p';
	    state->cf.cbname = strdup ("tls-unique");
	  }
	else
	  {
	    if (state->cbtlsuniquelen > 0)
	      state->cf.cbflag = 'y';
	    else
	      state->cf.cbflag = 'n';
	  }

	p = gsasl_property_get (sctx, GSASL_AUTHID);
	if (!p)
	  return GSASL_NO_AUTHID;

	rc = gsasl_saslprep (p, GSASL_ALLOW_UNASSIGNED,
			     &state->cf.username, NULL);
	if (rc != GSASL_OK)
	  return rc;

	p = gsasl_property_get (sctx, GSASL_AUTHZID);
	if (p)
	  state->cf.authzid = strdup (p);

	rc = scram_print_client_first (&state->cf, output);
	if (rc == -2)
	  return GSASL_MALLOC_ERROR;
	else if (rc != 0)
	  return GSASL_AUTHENTICATION_ERROR;

	*output_len = strlen (*output);

	/* Point p to client-first-message-bare. */
	p = strchr (*output, ',');
	if (!p)
	  return GSASL_AUTHENTICATION_ERROR;
	p++;
	p = strchr (p, ',');
	if (!p)
	  return GSASL_AUTHENTICATION_ERROR;
	p++;

	/* Save "client-first-message-bare" for the next step. */
	state->cfmb = strdup (p);
	if (!state->cfmb)
	  return GSASL_MALLOC_ERROR;

	/* Prepare B64("cbind-input") for the next step. */
	if (state->cf.cbflag == 'p')
	  {
	    size_t len = (p - *output) + state->cbtlsuniquelen;
	    char *cbind_input = malloc (len);
	    if (cbind_input == NULL)
	      return GSASL_MALLOC_ERROR;
	    memcpy (cbind_input, *output, p - *output);
	    memcpy (cbind_input + (p - *output), state->cbtlsunique,
		    state->cbtlsuniquelen);
	    rc = gsasl_base64_to (cbind_input, len, &state->cl.cbind, NULL);
	    free (cbind_input);
	  }
	else
	  rc = gsasl_base64_to (*output, p - *output, &state->cl.cbind, NULL);
	if (rc != 0)
	  return rc;

	/* We are done. */
	state->step++;
	return GSASL_NEEDS_MORE;
	break;
      }

    case 1:
      {
	if (scram_parse_server_first (input, input_len, &state->sf) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (strlen (state->sf.nonce) < strlen (state->cf.client_nonce) ||
	    memcmp (state->cf.client_nonce, state->sf.nonce,
		    strlen (state->cf.client_nonce)) != 0)
	  return GSASL_AUTHENTICATION_ERROR;

	state->cl.nonce = strdup (state->sf.nonce);
	if (!state->cl.nonce)
	  return GSASL_MALLOC_ERROR;

	/* Save salt/iter as properties, so that client callback can
	   access them. */
	{
	  char *str = NULL;
	  int n;
	  n = asprintf (&str, "%lu", (unsigned long) state->sf.iter);
	  if (n < 0 || str == NULL)
	    return GSASL_MALLOC_ERROR;
	  gsasl_property_set (sctx, GSASL_SCRAM_ITER, str);
	  free (str);
	}

	gsasl_property_set (sctx, GSASL_SCRAM_SALT, state->sf.salt);

	/* Generate ClientProof. */
	{
	  char saltedpassword[20];
	  char *clientkey;
	  char *storedkey;
	  char *clientsignature;
	  char clientproof[20];
	  const char *p;

	  /* Get SaltedPassword. */
	  p = gsasl_property_get (sctx, GSASL_SCRAM_SALTED_PASSWORD);
	  if (p && strlen (p) == 40 && hex_p (p))
	    sha1_hex_to_byte (saltedpassword, p);
	  else if ((p = gsasl_property_get (sctx, GSASL_PASSWORD)) != NULL)
	    {
	      Gc_rc err;
	      char *salt;
	      size_t saltlen;
	      char *preppasswd;

	      rc = gsasl_saslprep (p, 0, &preppasswd, NULL);
	      if (rc != GSASL_OK)
		return rc;

	      rc = gsasl_base64_from (state->sf.salt, strlen (state->sf.salt),
				      &salt, &saltlen);
	      if (rc != 0)
		{
		  gsasl_free (preppasswd);
		  return rc;
		}

	      /* SaltedPassword := Hi(password, salt) */
	      err = gc_pbkdf2_sha1 (preppasswd, strlen (preppasswd),
				    salt, saltlen,
				    state->sf.iter, saltedpassword, 20);
	      gsasl_free (preppasswd);
	      gsasl_free (salt);
	      if (err != GC_OK)
		return GSASL_MALLOC_ERROR;
	    }
	  else
	    return GSASL_NO_PASSWORD;

	  /* Get client-final-message-without-proof. */
	  {
	    char *cfmwp;
	    int n;

	    state->cl.proof = strdup ("p");
	    rc = scram_print_client_final (&state->cl, &cfmwp);
	    if (rc != 0)
	      return GSASL_MALLOC_ERROR;
	    free (state->cl.proof);

	    /* Compute AuthMessage */
	    n = asprintf (&state->authmessage, "%s,%.*s,%.*s",
			  state->cfmb,
			  (int) input_len, input,
			  (int) (strlen (cfmwp) - 4), cfmwp);
	    free (cfmwp);
	    if (n <= 0 || !state->authmessage)
	      return GSASL_MALLOC_ERROR;
	  }

	  /* ClientKey := HMAC(SaltedPassword, "Client Key") */
#define CLIENT_KEY "Client Key"
	  rc = gsasl_hmac_sha1 (saltedpassword, 20,
				CLIENT_KEY, strlen (CLIENT_KEY), &clientkey);
	  if (rc != 0)
	    return rc;

	  /* StoredKey := H(ClientKey) */
	  rc = gsasl_sha1 (clientkey, 20, &storedkey);
	  if (rc != 0)
	    {
	      free (clientkey);
	      return rc;
	    }

	  /* ClientSignature := HMAC(StoredKey, AuthMessage) */
	  rc = gsasl_hmac_sha1 (storedkey, 20,
				state->authmessage,
				strlen (state->authmessage),
				&clientsignature);
	  free (storedkey);
	  if (rc != 0)
	    {
	      free (clientkey);
	      return rc;
	    }

	  /* ClientProof := ClientKey XOR ClientSignature */
	  memcpy (clientproof, clientkey, 20);
	  memxor (clientproof, clientsignature, 20);

	  free (clientkey);
	  free (clientsignature);

	  rc = gsasl_base64_to (clientproof, 20, &state->cl.proof, NULL);
	  if (rc != 0)
	    return rc;

	  /* Generate ServerSignature, for comparison in next step. */
	  {
	    char *serverkey;
	    char *serversignature;

	    /* ServerKey := HMAC(SaltedPassword, "Server Key") */
#define SERVER_KEY "Server Key"
	    rc = gsasl_hmac_sha1 (saltedpassword, 20,
				  SERVER_KEY, strlen (SERVER_KEY),
				  &serverkey);
	    if (rc != 0)
	      return rc;

	    /* ServerSignature := HMAC(ServerKey, AuthMessage) */
	    rc = gsasl_hmac_sha1 (serverkey, 20,
				  state->authmessage,
				  strlen (state->authmessage),
				  &serversignature);
	    gsasl_free (serverkey);
	    if (rc != 0)
	      return rc;

	    rc = gsasl_base64_to (serversignature, 20,
				  &state->serversignature, NULL);
	    gsasl_free (serversignature);
	    if (rc != 0)
	      return rc;
	  }
	}

	rc = scram_print_client_final (&state->cl, output);
	if (rc != 0)
	  return GSASL_MALLOC_ERROR;

	*output_len = strlen (*output);

	state->step++;
	return GSASL_NEEDS_MORE;
	break;
      }

    case 2:
      {
	if (scram_parse_server_final (input, input_len, &state->sl) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (strcmp (state->sl.verifier, state->serversignature) != 0)
	  return GSASL_AUTHENTICATION_ERROR;

	state->step++;
	return GSASL_OK;
	break;
      }

    default:
      break;
    }

  return res;
}

void
_gsasl_scram_sha1_client_finish (Gsasl_session * sctx, void *mech_data)
{
  struct scram_client_state *state = mech_data;

  if (!state)
    return;

  free (state->cfmb);
  free (state->serversignature);
  free (state->authmessage);
  free (state->cbtlsunique);
  scram_free_client_first (&state->cf);
  scram_free_server_first (&state->sf);
  scram_free_client_final (&state->cl);
  scram_free_server_final (&state->sl);

  free (state);
}
