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
#include <netinet/in.h>
#endif

#define DEBUG 1

#define BITMAP_LEN 1
#define MAXBUF_LEN 4
#define RANDOM_LEN 16

#define MAXBUF_DEFAULT 65536

/* Client */

struct _Gsasl_kerberos_v5_client_state
{
  int step;
  int qop;
  int mutual;
  uint32_t servermaxbuf;
  char *serverrandom;
  Shishi *sh;
  Shishi_ticket *tkt;
  Shishi_as *as;
  Shishi_ap *ap;
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

  *mech_data = state;

  return GSASL_OK;
}

#define STEP_FIRST 0
#define STEP_WAITING_FOR_ASREP 1
#define STEP_WAITING_FOR_APREP 2

int
_gsasl_kerberos_v5_client_step (Gsasl_session_ctx * sctx,
				void *mech_data,
				const char *input,
				size_t input_len,
				char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;
  Gsasl_ctx *ctx;
  int res;

  /* XXX support infrastructure mode using shishi_ticketset_get_*()
     to get ticket and bypass the AS steps */

  switch (state->step)
    {
    case STEP_FIRST:
      if (input == NULL)
	{
	  *output_len = 0;
	  return GSASL_NEEDS_MORE;
	}

      if (input_len != BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN)
	return GSASL_MECHANISM_PARSE_ERROR;

      {
	unsigned char serverbitmap;

	memcpy (&serverbitmap, input, BITMAP_LEN);
	if (serverbitmap & GSASL_QOP_AUTH)
	  state->qop = GSASL_QOP_AUTH;
	else if (serverbitmap & GSASL_QOP_AUTH_INT)
	  state->qop = GSASL_QOP_AUTH_INT;
	else if (serverbitmap & GSASL_QOP_AUTH_CONF)
	  state->qop = GSASL_QOP_AUTH_CONF;
	else
	  return GSASL_MECHANISM_PARSE_ERROR;
	if (serverbitmap & (GSASL_QOP_AUTH | GSASL_QOP_AUTH_INT | GSASL_QOP_AUTH_CONF) & ~state->qop)	/* more than one QOP bit set? */
	  return GSASL_MECHANISM_PARSE_ERROR;
	if (serverbitmap & (1 << 3))
	  state->mutual = 1;
      }
      memcpy (&state->servermaxbuf, &input[BITMAP_LEN], MAXBUF_LEN);
      state->servermaxbuf = ntohl (state->servermaxbuf);
      state->serverrandom = malloc (RANDOM_LEN);
      if (state->serverrandom == NULL)
	return GSASL_MALLOC_ERROR;
      memcpy (state->serverrandom, &input[BITMAP_LEN + MAXBUF_LEN],
	      RANDOM_LEN);

      {
	int err;
	int n;

	err = shishi_as (state->sh, &state->as);
	if (err)
	  return GSASL_SHISHI_ERROR;
#if DEBUG
	shishi_kdcreq_print (state->sh, stderr, shishi_as_req (state->as));
#endif
	n = *output_len;
	err = shishi_a2d (state->sh, shishi_as_req (state->as), output, &n);
	if (err)
	  return GSASL_SHISHI_ERROR;
	*output_len = n;
      }
      state->step = STEP_WAITING_FOR_ASREP;

      res = GSASL_NEEDS_MORE;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
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
  char *random;
  int qop;
  Shishi_key *key;
  Shishi_key *sessionticketkey;
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

  err = shishi_key_random (state->sh, SHISHI_AES256_CTS_HMAC_SHA1_96,
			   &state->sessionticketkey);
  if (err)
    return GSASL_SHISHI_ERROR;

  state->firststep = 1;
  state->qop = GSASL_QOP_AUTH;

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
  Gsasl_ctx *ctx;
  ASN1_TYPE asn1;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_realm = gsasl_server_callback_realm_get (ctx);
  cb_qop = gsasl_server_callback_qop_get (ctx);
  cb_maxbuf = gsasl_server_callback_maxbuf_get (ctx);
  cb_retrieve = gsasl_server_callback_retrieve_get (ctx);

  if (state->firststep)
    {
      uint32_t tmp;
      int maxbuf;

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

      *output_len = BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN;

      if (output)
	{
	  unsigned char *p = &output[0];

	  /* XXX cb_qop() here when we support anything other than QOP_AUTH */
	  *p = 0;
	  if (state->qop == GSASL_QOP_AUTH)
	    *p |= 1 << 0;
	  else if (state->qop == GSASL_QOP_AUTH_INT)
	    *p |= 1 << 1;
	  else if (state->qop == GSASL_QOP_AUTH_CONF)
	    *p |= 1 << 2;
	  /* XXX we always require mutual authentication for now */
	  *p |= 1 << 3;
	}

      if (state->qop != GSASL_QOP_AUTH && cb_maxbuf)
	maxbuf = cb_maxbuf (sctx);
      else
	maxbuf = state->qop == GSASL_QOP_AUTH ? 0 : MAXBUF_DEFAULT;

      tmp = htonl (maxbuf);
      if (output)
	memcpy (&output[BITMAP_LEN], &tmp, MAXBUF_LEN);

      if (output)
	memcpy (&output[BITMAP_LEN + MAXBUF_LEN], state->random, RANDOM_LEN);

      state->firststep = 0;

      return GSASL_NEEDS_MORE;
    }

  /* XXX currently we only handle AS-REQ and AP-REQ in
     non-infrastructure mode.  Supporting infrastructure mode is
     simple, just send the AS-REQ to the KDC and wait for AS-REP
     instead of creating AS-REP locally. */

  if ((asn1 = shishi_d2a_asreq (state->sh, input, input_len)))
    {
      int err;
      ASN1_TYPE encticketpart, tkt, encasreppart, asrep;
      Shishi_ticket *ticket;

      /* Session key */
      err = shishi_key_random (state->sh, SHISHI_AES256_CTS_HMAC_SHA1_96,
			       &state->key);
      if (err)
	return GSASL_SHISHI_ERROR;

      /* EncTicketPart */
      encticketpart = shishi_encticketpart (state->sh);
      if (!encticketpart)
	return GSASL_SHISHI_ERROR;

      err = shishi_encticketpart_flags_set (state->sh, encticketpart, 0);
      if (err)
	return GSASL_SHISHI_ERROR;
      err = shishi_encticketpart_key_set (state->sh,
					  encticketpart, state->key);
      if (err)
	return GSASL_SHISHI_ERROR;

      err = shishi_encticketpart_crealm_set (state->sh, encticketpart, "foo");
      if (err)
	return GSASL_SHISHI_ERROR;

      err = shishi_encticketpart_cname_set (state->sh,
					    encticketpart,
					    SHISHI_NT_UNKNOWN, "jas");
      if (err)
	return GSASL_SHISHI_ERROR;


      err = shishi_encticketpart_transited_set (state->sh,
						encticketpart,
						SHISHI_TR_DOMAIN_X500_COMPRESS,
						"", 0);
      if (err)
	return GSASL_SHISHI_ERROR;


      err = shishi_encticketpart_authtime_set (state->sh,
					       encticketpart,
					       "20030131030002Z");
      if (err)
	return GSASL_SHISHI_ERROR;

      err = shishi_encticketpart_endtime_set (state->sh,
					      encticketpart,
					      "20030131030003Z");
      if (err)
	return GSASL_SHISHI_ERROR;

      err = shishi_encticketpart_print (state->sh, stdout, encticketpart);
      if (err)
	return GSASL_SHISHI_ERROR;

      /* Ticket */
      ticket = shishi_ticket (state->sh, NULL, NULL, NULL);
      if (!ticket)
	return GSASL_SHISHI_ERROR;

      shishi_ticket_encticketpart_set (ticket, encticketpart);

      tkt = shishi_asn1_ticket (state->sh);

      err = shishi_kdcreq_srealmserver_set (state->sh, tkt,
					    "realm", "server");
      if (err)
	return GSASL_SHISHI_ERROR;

      err = shishi_ticket_add_enc_part (state->sh, tkt,
					state->sessionticketkey,
					encticketpart);
      if (err)
	return GSASL_SHISHI_ERROR;

      err = shishi_asn1ticket_print (state->sh, stdout, tkt);
      if (err)
	return GSASL_SHISHI_ERROR;

      /* EncASRepPart */
      encasreppart = shishi_enckdcreppart (state->sh);
      if (!encasreppart)
	return GSASL_SHISHI_ERROR;

      err = shishi_enckdcreppart_print (state->sh, stdout, encasreppart);
      if (err)
	return GSASL_SHISHI_ERROR;

      /* AS-REP */
      asrep = shishi_asrep (state->sh);
      if (!asrep)
	return GSASL_SHISHI_ERROR;

      err = shishi_kdcrep_set_ticket (state->sh, asrep, tkt);
      if (err)
	return GSASL_SHISHI_ERROR;

      err = shishi_kdcrep_print (state->sh, stdout, asrep);
      if (err)
	return GSASL_SHISHI_ERROR;
    }
  else if ((asn1 = shishi_d2a_apreq (state->sh, input, input_len)))
    {
      puts ("apreq");
    }
  puts ("urk");

  *output_len = 0;
  return GSASL_NEEDS_MORE;
}

int
_gsasl_kerberos_v5_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;

  shishi_done (state->sh);
  free (state->random);
  free (state);

  return GSASL_OK;
}

#endif /* USE_KERBEROS_V5 */
