/* kerberos_v5.c      implementation of experimental SASL mechanism KERBEROS_V5
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with GNU SASL; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "kerberos_v5.h"

#ifdef USE_KERBEROS_V5

#include <shishi.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h> /* ntohl */
#endif

#define DEBUG 0

#define BITMAP_LEN 1
#define MAXBUF_LEN 4
#define RANDOM_LEN 16
#define MUTUAL (1 << 3)

#define SERVER_HELLO_LEN BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN
#define CLIENT_HELLO_LEN BITMAP_LEN + MAXBUF_LEN

#define MAXBUF_DEFAULT 65536

/* Client */

struct _Gsasl_kerberos_v5_client_state
{
  int step;
  char serverhello[BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN];
  int serverqops;
  int clientqop;
  int servermutual;
  uint32_t servermaxbuf;
  uint32_t clientmaxbuf;
  Shishi *sh;
  Shishi_tkt *tkt;
  Shishi_as *as;
  Shishi_ap *ap;
  Shishi_key *sessionkey;
  Shishi_safe *safe;
};

int
_gsasl_kerberos_v5_client_init (Gsasl_ctx * ctx)
{
  if (!shishi_check_version (SHISHI_VERSION))
    return GSASL_UNKNOWN_MECHANISM;

  return GSASL_OK;
}

void
_gsasl_kerberos_v5_client_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_kerberos_v5_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  struct _Gsasl_kerberos_v5_client_state *state;
  Gsasl_ctx *ctx;
  int err;

  state = malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  memset (state, 0, sizeof (*state));

  err = shishi_init (&state->sh);
  if (err)
    return GSASL_KERBEROS_V5_INIT_ERROR;

  state->step = 0;
  state->clientqop = GSASL_QOP_AUTH_INT;

  *mech_data = state;

  return GSASL_OK;
}

#define STEP_FIRST 0
#define STEP_NONINFRA_SEND_ASREQ 1
#define STEP_NONINFRA_WAIT_ASREP 2
#define STEP_NONINFRA_SEND_APREQ 3
#define STEP_NONINFRA_WAIT_APREP 4
#define STEP_SUCCESS 5

int
_gsasl_kerberos_v5_client_step (Gsasl_session_ctx * sctx,
				void *mech_data,
				const char *input,
				size_t input_len,
				char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;
  Gsasl_client_callback_authentication_id cb_authentication_id;
  Gsasl_client_callback_authorization_id cb_authorization_id;
  Gsasl_client_callback_qop cb_qop;
  Gsasl_client_callback_realm cb_realm;
  Gsasl_client_callback_password cb_password;
  Gsasl_client_callback_service cb_service;
  Gsasl_client_callback_maxbuf cb_maxbuf;
  Gsasl_ctx *ctx;
  int res;
  int len;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  /* These are optional */
  cb_realm = gsasl_client_callback_realm_get (ctx);
  cb_service = gsasl_client_callback_service_get (ctx);
  cb_authentication_id = gsasl_client_callback_authentication_id_get (ctx);
  cb_authorization_id = gsasl_client_callback_authorization_id_get (ctx);
  cb_qop = gsasl_client_callback_qop_get (ctx);
  cb_maxbuf = gsasl_client_callback_maxbuf_get (ctx);

  /* Only optionally needed in infrastructure mode */
  cb_password = gsasl_client_callback_password_get (ctx);
  if (cb_password == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  /* I think we really need this one */
  cb_service = gsasl_client_callback_service_get (ctx);
  if (cb_service == NULL)
    return GSASL_NEED_CLIENT_SERVICE_CALLBACK;

  switch (state->step)
    {
    case STEP_FIRST:
      if (input == NULL)
	{
	  *output_len = 0;
	  return GSASL_NEEDS_MORE;
	}

      if (input_len != SERVER_HELLO_LEN)
	return GSASL_MECHANISM_PARSE_ERROR;

      memcpy(state->serverhello, input, input_len);

      {
	unsigned char serverbitmap;

	memcpy (&serverbitmap, input, BITMAP_LEN);
	state->serverqops = 0;
	if (serverbitmap & GSASL_QOP_AUTH)
	  state->serverqops |= GSASL_QOP_AUTH;
	if (serverbitmap & GSASL_QOP_AUTH_INT)
	  state->serverqops |= GSASL_QOP_AUTH_INT;
	if (serverbitmap & GSASL_QOP_AUTH_CONF)
	  state->serverqops |= GSASL_QOP_AUTH_CONF;
	if (serverbitmap & MUTUAL)
	  state->servermutual = 1;
      }
      memcpy (&state->servermaxbuf, &input[BITMAP_LEN], MAXBUF_LEN);
      state->servermaxbuf = ntohl (state->servermaxbuf);

      if (cb_qop)
	state->clientqop = cb_qop (sctx, state->serverqops);

      if (!(state->serverqops & state->clientqop &
	    (GSASL_QOP_AUTH|GSASL_QOP_AUTH_INT|GSASL_QOP_AUTH_CONF)))
	return GSASL_AUTHENTICATION_ERROR;

      /* XXX for now we require server authentication */
      if (!state->servermutual)
	return GSASL_AUTHENTICATION_ERROR;

      /* Decide policy here: non-infrastructure, infrastructure or proxy.
       *
       * A callback to decide should be added, but without the default
       * should be:
       *
       * IF shishi_tktset_get_for_server() THEN
       *    INFRASTRUCTURE MODE
       * ELSE IF shishi_realm_for_server(server) THEN
       *    PROXY INFRASTRUCTURE (then fallback to NIM?)
       * ELSE
       *    NON-INFRASTRUCTURE MODE
       */
      state->step = STEP_NONINFRA_SEND_APREQ; /* only NIM for now.. */
      /* fall through */

    case STEP_NONINFRA_SEND_ASREQ:
      res = shishi_as (state->sh, &state->as);
      if (res)
	return GSASL_SHISHI_ERROR;

      if (cb_authentication_id) /* Shishi defaults to one otherwise */
	{
	  len = *output_len - 1;
	  res = cb_authentication_id (sctx, output, &len);
	  if (res != GSASL_OK)
	    return res;
	  output[len] = '\0';

	  res = shishi_kdcreq_set_cname (state->sh, shishi_as_req(state->as),
					 SHISHI_NT_UNKNOWN, output);
	  if (res != GSASL_OK)
	    return res;
	}

      if (cb_realm)
	{
	  len = *output_len - 1;
	  res = cb_realm (sctx, output, &len);
	  if (res != GSASL_OK)
	    return res;
	}
      else
	len = 0;

      output[len] = '\0';
      res = shishi_kdcreq_set_realm (state->sh, shishi_as_req(state->as),
				     output);
      if (res != GSASL_OK)
	return res;

      if (cb_service)
	{
	  char *sname[3];
	  size_t servicelen = 0;
	  size_t hostnamelen = 0;

	  res = cb_service (sctx, NULL, &servicelen, NULL, &hostnamelen,
			    /* XXX support servicename a'la DIGEST-MD5 too? */
			    NULL, NULL);
	  if (res != GSASL_OK)
	    return res;

	  if (*output_len < servicelen + 1 + hostnamelen + 1)
	    return GSASL_TOO_SMALL_BUFFER;

	  sname[0] = &output[0];
	  sname[1] = &output[servicelen+2];
	  sname[2] = NULL;

	  res = cb_service (sctx, sname[0], &servicelen,
			    sname[1], &hostnamelen,
			    NULL, NULL);
	  if (res != GSASL_OK)
	    return res;

	  sname[0][servicelen] = '\0';
	  sname[1][hostnamelen] = '\0';

	  res = shishi_kdcreq_set_sname (state->sh, shishi_as_req(state->as),
					 SHISHI_NT_UNKNOWN, sname);
	  if (res != GSASL_OK)
	    return res;
	}

      /* XXX query application for encryption types and set the etype
	 field?  Already configured by shishi though... */

      res = shishi_a2d (state->sh, shishi_as_req (state->as),
			output, output_len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      state->step = STEP_NONINFRA_WAIT_ASREP;

      res = GSASL_NEEDS_MORE;
      break;

    case STEP_NONINFRA_WAIT_ASREP:
      if (shishi_as_rep_der_set (state->as, input, input_len) != SHISHI_OK)
	return GSASL_MECHANISM_PARSE_ERROR;

      /* XXX? password stored in callee's output buffer */
      len = *output_len - 1;
      res = cb_password (sctx, output, &len);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	return res;
      output[len] = '\0';

      res = shishi_as_rep_process (state->as, NULL, output);
      if (res != SHISHI_OK)
	return GSASL_AUTHENTICATION_ERROR;

      state->step = STEP_NONINFRA_SEND_APREQ;
      /* fall through */

    case STEP_NONINFRA_SEND_APREQ:
      if (*output_len <= CLIENT_HELLO_LEN + SERVER_HELLO_LEN)
	return GSASL_TOO_SMALL_BUFFER;

      if (!(state->clientqop & ~GSASL_QOP_AUTH))
	state->clientmaxbuf = 0;
      else if (cb_maxbuf)
	state->clientmaxbuf = cb_maxbuf (sctx, state->servermaxbuf);
      else
	state->clientmaxbuf = MAXBUF_DEFAULT;

      /* XXX for now we require server authentication */
      output[0] = state->clientqop|MUTUAL;
      {
	uint32_t tmp;

	tmp = ntohl (state->clientmaxbuf);
	memcpy(&output[BITMAP_LEN], &tmp, MAXBUF_LEN);
      }
      memcpy(&output[CLIENT_HELLO_LEN], state->serverhello, SERVER_HELLO_LEN);

      if (cb_authorization_id)
	{
	  len = *output_len - CLIENT_HELLO_LEN + SERVER_HELLO_LEN;
	  res = cb_authorization_id (sctx, &output[CLIENT_HELLO_LEN +
						   SERVER_HELLO_LEN], &len);
	}
      else
	len = 0;

      len += CLIENT_HELLO_LEN + SERVER_HELLO_LEN;
      res = shishi_ap_tktoptionsdata (state->sh,
				      &state->ap,
				      shishi_as_tkt(state->as),
				      SHISHI_APOPTIONS_MUTUAL_REQUIRED,
				      output, len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_authenticator_add_authorizationdata
	(state->sh, shishi_ap_authenticator(state->ap),
	 -1, output, len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      /* XXX set realm in AP-REQ and Authenticator */

      res = shishi_ap_req_der (state->ap, output, output_len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      state->step = STEP_NONINFRA_WAIT_APREP;

      res = GSASL_NEEDS_MORE;
      break;

    case STEP_NONINFRA_WAIT_APREP:
      if (shishi_ap_rep_der_set (state->ap, input, input_len) != SHISHI_OK)
	return GSASL_MECHANISM_PARSE_ERROR;

      res = shishi_ap_rep_verify (state->ap);
      if (res != SHISHI_OK)
	return GSASL_AUTHENTICATION_ERROR;

      state->step = STEP_SUCCESS;

      /* XXX support AP session keys */
      state->sessionkey = shishi_tkt_key (shishi_as_tkt (state->as));

      *output_len = 0;
      res = GSASL_OK;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

int
_gsasl_kerberos_v5_client_encode (Gsasl_session_ctx * sctx,
				  void *mech_data,
				  const char *input,
				  size_t input_len,
				  char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;
  int res;

  if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_CONF)
    {
      /* XXX */
    }
  else if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_INT)
    {
      res = shishi_safe (state->sh, &state->safe);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_set_user_data (state->sh,
				       shishi_safe_safe (state->safe),
				       input, input_len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_build (state->safe, state->sessionkey);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_safe_der (state->safe, output, output_len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;
    }
  else
    {
      *output_len = input_len;
      if (output)
	memcpy (output, input, input_len);
      return GSASL_OK;
    }

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_client_decode (Gsasl_session_ctx * sctx,
				  void *mech_data,
				  const char *input,
				  size_t input_len,
				  char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;

  puts("cdecode");

  if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_CONF)
    {
      /* XXX */
    }
  else if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_INT)
    {
      puts("decode");
    }
  else
    {
      *output_len = input_len;
      if (output)
	memcpy (output, input, input_len);
      return GSASL_OK;
    }

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_client_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;

  shishi_done (state->sh);
  free (state);

  return GSASL_OK;
}

/* Server */

struct _Gsasl_kerberos_v5_server_state
{
  int firststep;
  Shishi *sh;
  char serverhello[BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN];
  char *random;
  int serverqops;
  uint32_t servermaxbuf;
  int clientqop;
  int clientmutual;
  uint32_t clientmaxbuf;
  char *username;
  char *userrealm;
  char *serverrealm;
  char *serverservice;
  char *serverhostname;
  char *password;
  Shishi_key *userkey; /* user's key derived with string2key */
  Shishi_key *sessionkey; /* shared between client and server */
  Shishi_key *sessiontktkey; /* known only by server */
  Shishi_ap *ap;
  Shishi_as *as;
  Shishi_safe *safe;
};

int
_gsasl_kerberos_v5_server_init (Gsasl_ctx * ctx)
{
  if (!shishi_check_version (SHISHI_VERSION))
    return GSASL_UNKNOWN_MECHANISM;

  return GSASL_OK;
}

void
_gsasl_kerberos_v5_server_done (Gsasl_ctx * ctx)
{
  return;
}

int
_gsasl_kerberos_v5_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  struct _Gsasl_kerberos_v5_server_state *state;
  int err;

  state = malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;
  memset (state, 0, sizeof (*state));

  state->random = (char *) malloc (RANDOM_LEN);
  if (state->random == NULL)
    return GSASL_MALLOC_ERROR;

  err = shishi_init_server (&state->sh);
  if (err)
    return GSASL_KERBEROS_V5_INIT_ERROR;

  err = shishi_randomize (state->sh, state->random, RANDOM_LEN);
  if (err)
    return GSASL_SHISHI_ERROR;

  /* This can be pretty much anything, the client will never have it. */
  err = shishi_key_random (state->sh, SHISHI_AES256_CTS_HMAC_SHA1_96,
			   &state->sessiontktkey);
  if (err)
    return GSASL_SHISHI_ERROR;

  err = shishi_as (state->sh, &state->as);
  if (err)
    return GSASL_SHISHI_ERROR;

  state->firststep = 1;
  state->serverqops = GSASL_QOP_AUTH | GSASL_QOP_AUTH_INT;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_server_step (Gsasl_session_ctx * sctx,
				void *mech_data,
				const char *input,
				size_t input_len,
				char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;
  Gsasl_server_callback_realm cb_realm;
  Gsasl_server_callback_qop cb_qop;
  Gsasl_server_callback_maxbuf cb_maxbuf;
  Gsasl_server_callback_cipher cb_cipher;
  Gsasl_server_callback_retrieve cb_retrieve;
  Gsasl_server_callback_service cb_service;
  unsigned char buf[BUFSIZ];
  size_t buflen;
  Gsasl_ctx *ctx;
  ASN1_TYPE asn1;
  int err;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_realm = gsasl_server_callback_realm_get (ctx);
  cb_qop = gsasl_server_callback_qop_get (ctx);
  cb_maxbuf = gsasl_server_callback_maxbuf_get (ctx);
  cb_retrieve = gsasl_server_callback_retrieve_get (ctx);
  cb_service = gsasl_server_callback_service_get (ctx);
  if (cb_service == NULL)
    return GSASL_NEED_SERVER_SERVICE_CALLBACK;

  if (state->firststep)
    {
      uint32_t tmp;
      unsigned char *p;

      /*
       * The initial server packet should contain one octet containing
       * a bit mask of supported security layers, four octets
       * indicating the maximum cipher-text buffer size the server is
       * able to receive (or 0 if no security layers are supported) in
       * network byte order, and then 16 octets containing random data
       * (see [4] on how random data might be generated).
       *
       * The security layers and their corresponding bit-masks are as
       * follows:
       *
       *       Bit 0 No security layer
       *       Bit 1 Integrity (KRB-SAFE) protection
       *       Bit 2 Privacy (KRB-PRIV) protection
       *       Bit 3 Mutual authentication is required (AP option MUTUAL-
       *             REQUIRED must also be present).
       *
       * Other bit-masks may be defined in the future; bits which are
       * not understood must be negotiated off.
       *
       */
      if (output && *output_len < BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN)
	return GSASL_TOO_SMALL_BUFFER;

      p = &state->serverhello[0];

      if (cb_qop)
	state->serverqops = cb_qop (sctx);
      *p = 0;
      if (state->serverqops & GSASL_QOP_AUTH)
	*p |= GSASL_QOP_AUTH;
      if (state->serverqops & GSASL_QOP_AUTH_INT)
	*p |= GSASL_QOP_AUTH_INT;
      if (state->serverqops & GSASL_QOP_AUTH_CONF)
	*p |= GSASL_QOP_AUTH_CONF;
      /* XXX we always require mutual authentication for now */
      *p |= MUTUAL;

      if (!(state->serverqops & ~GSASL_QOP_AUTH))
	state->servermaxbuf = 0;
      else if (cb_maxbuf)
	state->servermaxbuf = cb_maxbuf (sctx);
      else
	state->servermaxbuf = MAXBUF_DEFAULT;

      tmp = htonl (state->servermaxbuf);
      memcpy (&state->serverhello[BITMAP_LEN], &tmp, MAXBUF_LEN);
      memcpy (&state->serverhello[BITMAP_LEN + MAXBUF_LEN],
	      state->random, RANDOM_LEN);

      if (output)
	memcpy(output, state->serverhello, SERVER_HELLO_LEN);
      *output_len = BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN;

      state->firststep = 0;

      return GSASL_NEEDS_MORE;
    }

  if (cb_retrieve)
    {
      /* Non-infrastructure mode */

      if (*output_len < 2048)
	return GSASL_TOO_SMALL_BUFFER;

      if (shishi_as_req_der_set(state->as, input, input_len) == SHISHI_OK)
	{
	  Shishi_tkt *tkt;
	  int etype, i;

	  tkt = shishi_as_tkt (state->as);
	  if (!tkt)
	    return GSASL_SHISHI_ERROR;

	  i = 1;
	  do {
	    err = shishi_kdcreq_etype (state->sh,
				       shishi_as_req(state->as),
				       &etype, i);
	    if (err == SHISHI_OK && shishi_cipher_supported_p (etype))
	      break;
	  } while (err == SHISHI_OK);
	  if (err != SHISHI_OK)
	    return err;

	  /* XXX use a "preferred server kdc etype" from shishi instead? */
	  err = shishi_key_random (state->sh, etype, &state->sessionkey);
	  if (err)
	    return GSASL_SHISHI_ERROR;

	  err = shishi_tkt_key_set (tkt, state->sessionkey);
	  if (err)
	    return GSASL_SHISHI_ERROR;

	  buflen = sizeof (buf) - 1;
	  err = shishi_kdcreq_cname_get (state->sh,
					 shishi_as_req(state->as),
					 buf, &buflen);
	  if (err != SHISHI_OK)
	    return err;
	  buf[buflen] = '\0';
	  state->username = strdup(buf);

	  buflen = sizeof (buf) - 1;
	  err = shishi_kdcreq_realm_get (state->sh,
					  shishi_as_req(state->as),
					  buf, &buflen);
	  if (err != SHISHI_OK)
	    return err;
	  buf[buflen] = '\0';
	  state->userrealm = strdup(buf);

	  buflen = sizeof (buf) - 1;
	  err = cb_retrieve (sctx, state->username, NULL, state->userrealm,
			     NULL, &buflen);
	  if (err != GSASL_OK)
	    return err;

	  state->password = malloc (buflen + 1);
	  if (state->password == NULL)
	    return GSASL_MALLOC_ERROR;

	  err = cb_retrieve (sctx, state->username, NULL, state->userrealm,
			     state->password, &buflen);
	  if (err != GSASL_OK)
	    return err;
	  state->password[buflen] = '\0';

	  buflen = sizeof (buf) - 1;
	  if (cb_realm)
	    {
	      err = cb_realm (sctx, buf, &buflen, 0);
	      if (err != GSASL_OK)
		return err;
	    }
	  else
	    buflen = 0;
	  buf[buflen] = '\0';
	  state->serverrealm = strdup(buf);

	  buflen = sizeof (buf) - 1;
	  err = cb_service (sctx, buf, &buflen, NULL, NULL);
	  if (err != GSASL_OK)
	    return err;
	  buf[buflen] = '\0';
	  state->serverservice = strdup(buf);

	  buflen = sizeof (buf) - 1;
	  err = cb_service (sctx, NULL, NULL, buf, &buflen);
	  if (err != GSASL_OK)
	    return err;
	  buf[buflen] = '\0';
	  state->serverhostname = strdup(buf);

	  /* XXX do some checking on realm and server name?  Right now
	     we simply doesn't care about what client requested and
	     return a ticket for this server.  This is bad. */

	  err = shishi_tkt_clientrealm_set (tkt, state->userrealm,
					       state->username);
	  if (err)
	    return GSASL_SHISHI_ERROR;

	  {
	    char *p;
	    p = malloc(strlen(state->serverservice) + strlen("/") +
		       strlen(state->serverhostname) + 1);
	    if (p == NULL)
	      return GSASL_MALLOC_ERROR;
	    sprintf(p, "%s/%s", state->serverservice, state->serverhostname);
	    err = shishi_tkt_serverrealm_set (tkt,
						 state->serverrealm, p);
	    free(p);
	    if (err)
	      return GSASL_SHISHI_ERROR;
	  }

	  buflen = sizeof (buf);
	  err = shishi_as_derive_salt (state->sh,
				       shishi_as_req(state->as),
				       shishi_as_rep(state->as),
				       buf, &buflen);
	  if (err != SHISHI_OK)
	    return err;

	  err = shishi_key_from_string (state->sh,
					etype,
					state->password,
					strlen(state->password),
					buf, buflen,
					NULL, &state->userkey);
	  if (err != SHISHI_OK)
	    return err;

	  err = shishi_tkt_build (tkt, state->sessiontktkey);
	  if (err)
	    return GSASL_SHISHI_ERROR;

	  err = shishi_as_rep_build (state->as, state->userkey);
	  if (err)
	    return GSASL_SHISHI_ERROR;

#if DEBUG
	  shishi_kdcreq_print (state->sh, stderr, shishi_as_req(state->as));
	  shishi_encticketpart_print (state->sh, stderr,
				      shishi_tkt_encticketpart (tkt));
	  shishi_ticket_print (state->sh, stderr, shishi_tkt_ticket (tkt));
	  shishi_enckdcreppart_print (state->sh, stderr,
				      shishi_tkt_enckdcreppart (state->as));
	  shishi_kdcrep_print (state->sh, stderr, shishi_as_rep(state->as));
#endif

	  err = shishi_as_rep_der (state->as, output, output_len);
	  if (err)
	    return GSASL_SHISHI_ERROR;

	  return GSASL_NEEDS_MORE;
	}
      else if ((asn1 = shishi_der2asn1_apreq (state->sh, input, input_len)))
	{
	  int adtype;

	  err = shishi_ap (state->sh, &state->ap);
	  if (err)
	    return GSASL_SHISHI_ERROR;

	  shishi_ap_req_set (state->ap, asn1);

	  err = shishi_ap_req_process (state->ap, state->sessiontktkey);
	  if (err)
	    return GSASL_SHISHI_ERROR;

#if DEBUG
	  shishi_apreq_print(state->sh, stderr, shishi_ap_req (state->ap));
	  shishi_ticket_print (state->sh, stderr,
			       shishi_tkt_ticket(shishi_ap_tkt (state->ap)));
	  shishi_authenticator_print(state->sh, stderr,
				     shishi_ap_authenticator (state->ap));
#endif

	  buflen = sizeof(buf);
	  err = shishi_authenticator_authorizationdata
	    (state->sh, shishi_ap_authenticator(state->ap),
	     &adtype, buf, &buflen, 1);
	  if (err)
	    return GSASL_SHISHI_ERROR;

	  if (adtype != 0xFF /* -1 in one-complements form */ ||
	      buflen < CLIENT_HELLO_LEN + SERVER_HELLO_LEN)
	    return GSASL_AUTHENTICATION_ERROR;

	  {
	    unsigned char clientbitmap;

	    memcpy (&clientbitmap, &buf[0], BITMAP_LEN);
	    state->clientqop = 0;
	    if (clientbitmap & GSASL_QOP_AUTH)
	      state->clientqop |= GSASL_QOP_AUTH;
	    if (clientbitmap & GSASL_QOP_AUTH_INT)
	      state->clientqop |= GSASL_QOP_AUTH_INT;
	    if (clientbitmap & GSASL_QOP_AUTH_CONF)
	      state->clientqop |= GSASL_QOP_AUTH_CONF;
	    if (clientbitmap & MUTUAL)
	      state->clientmutual = 1;
	  }
	  memcpy (&state->clientmaxbuf, &input[BITMAP_LEN], MAXBUF_LEN);
	  state->clientmaxbuf = ntohl (state->clientmaxbuf);

	  if (!(state->clientqop & state->serverqops))
	    return GSASL_AUTHENTICATION_ERROR;

	  /* XXX check clientmaxbuf too */

	  if (memcmp(&buf[CLIENT_HELLO_LEN],
		     state->serverhello,
		     SERVER_HELLO_LEN) != 0)
	    return GSASL_AUTHENTICATION_ERROR;

	  {
	    char cksum[BUFSIZ];
	    int cksumlen;
	    int cksumtype;
	    Shishi_key *key;

	    key = shishi_tkt_key (shishi_as_tkt(state->as));
	    cksumtype = shishi_cipher_defaultcksumtype (shishi_key_type (key));
	    cksumlen = sizeof (cksum);
	    err = shishi_checksum (state->sh, key,
				   SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR_CKSUM,
				   cksumtype, buf, buflen, cksum, &cksumlen);
	    if (err != SHISHI_OK)
	      return GSASL_SHISHI_ERROR;

	    buflen = sizeof(buf);
	    err = shishi_authenticator_cksum
	      (state->sh,
	       shishi_ap_authenticator(state->ap),
	       &cksumtype, buf, &buflen);
	    if (err != SHISHI_OK)
	      return GSASL_SHISHI_ERROR;

	    if (buflen != cksumlen ||
		memcmp(buf, cksum, buflen) != 0)
	      return GSASL_AUTHENTICATION_ERROR;
	  }

	  /* XXX use authorization_id */

	  if (state->clientmutual)
	    {
	      err = shishi_ap_rep_build (state->ap);
	      if (err)
		return GSASL_SHISHI_ERROR;

	      err = shishi_ap_rep_der (state->ap, output, output_len);
	      if (err)
		return GSASL_SHISHI_ERROR;
	    }
	  else
	    *output_len = 0;

	  return GSASL_OK;
	}
    }
  else
    {
      /* XXX Currently we only handle AS-REQ and AP-REQ in
	 non-infrastructure mode.  Supporting infrastructure mode is
	 simple, just send the AS-REQ to the KDC and wait for AS-REP
	 instead of creating AS-REP locally.

	 We should probably have a callback to decide policy:
	 1) non-infrastructure mode (NIM) only
	 2) infrastructure mode (IM) only
	 3) proxied infrastructure mode (PIM) only
	 4) NIM with fallback to IM (useful for local server overrides)
	 5) IM with fallback to NIM (useful for admins if KDC is offline)
	 6) ...etc with PIM too
      */
      return GSASL_NEED_SERVER_RETRIEVE_CALLBACK;
    }

  *output_len = 0;
  return GSASL_NEEDS_MORE;
}

int
_gsasl_kerberos_v5_server_encode (Gsasl_session_ctx * sctx,
				  void *mech_data,
				  const char *input,
				  size_t input_len,
				  char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;
  int res;

  if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_CONF)
    {
      /* XXX */
    }
  else if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_INT)
    {
      res = shishi_safe (state->sh, &state->safe);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_set_user_data (state->sh,
				       shishi_safe_safe (state->safe),
				       input, input_len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_build (state->safe, state->sessionkey);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_safe_der (state->safe, output, output_len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;
    }
  else
    {
      *output_len = input_len;
      if (output)
	memcpy (output, input, input_len);
      return GSASL_OK;
    }

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_server_decode (Gsasl_session_ctx * sctx,
				  void *mech_data,
				  const char *input,
				  size_t input_len,
				  char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;
  int res;

  if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_CONF)
    {
      /* XXX */
    }
  else if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_INT)
    {
      Shishi_asn1 asn1safe;

      res = shishi_safe (state->sh, &state->safe);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_safe_der_set (state->safe, input, input_len);
      printf("len %d err %d\n", input_len, res);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_verify (state->safe, state->sessionkey);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;

      res = shishi_safe_user_data (state->sh, shishi_safe_safe (state->safe),
				   output, output_len);
      if (res != SHISHI_OK)
	return GSASL_SHISHI_ERROR;
      printf("len=%d\n", *output_len);
      return GSASL_OK;
    }
  else
    {
      *output_len = input_len;
      if (output)
	memcpy (output, input, input_len);
      return GSASL_OK;
    }


  return GSASL_OK;
}

int
_gsasl_kerberos_v5_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;

  shishi_done (state->sh);
  if (state->username)
    free (state->username);
  if (state->password)
    free (state->password);
  if (state->random)
    free (state->random);
  free (state);

  return GSASL_OK;
}

#endif /* USE_KERBEROS_V5 */
