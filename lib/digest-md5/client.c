/* client.c --- DIGEST-MD5 mechanism from RFC 2831, client side.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
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
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA
 *
 */

#include "digest-md5.h"

#include "shared.h"

#include "session.h"

struct _Gsasl_digest_md5_client_state
{
  int step;
  char secret[MD5LEN];
  char *nonce;
  uint32_t nc;
  char cnonce[2 * CNONCE_ENTROPY_BITS / 8 + 1];
  Gsasl_qop qop;
  Gsasl_cipher cipher;
  char *authzid;
  char *digesturi;
  char response[RESPONSE_LENGTH + 1];
  uint32_t readseqnum, sendseqnum;
  char kic[MD5LEN];
  char kcc[MD5LEN];
  char kis[MD5LEN];
  char kcs[MD5LEN];
};
typedef struct _Gsasl_digest_md5_client_state _Gsasl_digest_md5_client_state;

int
_gsasl_digest_md5_client_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  _Gsasl_digest_md5_client_state *state;
  Gsasl_ctx *ctx;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  if (gsasl_client_callback_authentication_id_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

  if (gsasl_client_callback_password_get (ctx) == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  state = (_Gsasl_digest_md5_client_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;
  state->nonce = NULL;
  state->nc = 1;
  state->cipher = 0;
  state->qop = GSASL_QOP_AUTH;
  state->authzid = NULL;
  state->digesturi = NULL;
  state->readseqnum = 0;
  state->sendseqnum = 0;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_digest_md5_client_step (Gsasl_session_ctx * sctx,
			       void *mech_data,
			       const char *input,
			       size_t input_len,
			       char **output2, size_t * output2_len)
{
  _Gsasl_digest_md5_client_state *state = mech_data;
  Gsasl_client_callback_authorization_id cb_authorization_id;
  Gsasl_client_callback_authentication_id cb_authentication_id;
  Gsasl_client_callback_password cb_password;
  Gsasl_client_callback_service cb_service;
  Gsasl_client_callback_qop cb_qop;
  Gsasl_client_callback_maxbuf cb_maxbuf;
  char *subopts;
  char *value;
  Gsasl_ctx *ctx;
  int outlen;
  int res, i;
  /* FIXME: Remove fixed size buffer. */
  char output[BUFSIZ];
  size_t outputlen = BUFSIZ - 1;
  size_t *output_len = &outputlen;

  *output2 = NULL;
  *output2_len = 0;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_qop = gsasl_client_callback_qop_get (ctx);
  cb_authorization_id = gsasl_client_callback_authorization_id_get (ctx);
  cb_maxbuf = gsasl_client_callback_maxbuf_get (ctx);

  cb_authentication_id = gsasl_client_callback_authentication_id_get (ctx);
  if (cb_authentication_id == NULL)
    return GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK;

  cb_password = gsasl_client_callback_password_get (ctx);
  if (cb_password == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  cb_service = gsasl_client_callback_service_get (ctx);
  if (cb_service == NULL)
    return GSASL_NEED_CLIENT_SERVICE_CALLBACK;

  if (*output_len < 1)
    return GSASL_TOO_SMALL_BUFFER;

  strcpy (output, "");
  outlen = 0;

#if CLIENT_PRINT_OUTPUT
  if (input && input_len > 0)
    fprintf (stderr, "%s\n", input);
#endif

  switch (state->step)
    {
    case 0:
      state->step++;
      if (input_len == 0)
	{
	  *output_len = 0;
	  return GSASL_NEEDS_MORE;
	}
      /* fall through */

    case 1:
      {
	char **realm = NULL;
	size_t nrealm = 0;
	long maxbuf = -1;
	char *zinput = NULL;

	if (input == NULL || input_len == 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	zinput = malloc (input_len + 1);
	if (zinput == NULL)
	  return GSASL_MALLOC_ERROR;
	memcpy (zinput, input, input_len);
	zinput[input_len] = '\0';

	gsasl_nonce (state->cnonce, CNONCE_ENTROPY_BITS / 8);
	for (i = 0; i < CNONCE_ENTROPY_BITS / 8; i++)
	  {
	    state->cnonce[CNONCE_ENTROPY_BITS / 8 + i] =
	      HEXCHAR (state->cnonce[i]);
	    state->cnonce[i] = HEXCHAR (state->cnonce[i] >> 4);
	  }
	state->cnonce[2 * CNONCE_ENTROPY_BITS / 8] = '\0';

	subopts = zinput;
	while (*subopts != '\0')
	  switch (_gsasl_getsubopt (&subopts, digest_challenge_opts, &value))
	    {
	    case CHALLENGE_REALM:
	      if (nrealm == 0)
		realm = (char **) malloc (sizeof (*realm));
	      else
		realm = realloc (realm, (nrealm + 1) * sizeof (*realm));
	      if (realm == NULL)
		{
		  res = GSASL_MALLOC_ERROR;
		  goto done;
		}
	      realm[nrealm] = strdup (value);
	      nrealm++;
	      break;

	    case CHALLENGE_NONCE:
	      if (state->nonce != NULL)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      state->nonce = strdup (value);
	      break;

	    case CHALLENGE_QOP:
	      {
		char *subsubopts;
		char *val;

		state->qop = 0;
		subsubopts = value;
		while (*subsubopts != '\0')
		  switch (_gsasl_getsubopt (&subsubopts, qop_opts, &val))
		    {
		    case QOP_AUTH_OPTION:
		      state->qop |= GSASL_QOP_AUTH;
		      break;

		    case QOP_AUTH_INT_OPTION:
		      state->qop |= GSASL_QOP_AUTH_INT;
		      break;

		    case QOP_AUTH_CONF_OPTION:
		      state->qop |= GSASL_QOP_AUTH_CONF;
		      break;

		    default:
		      /* Ignore unknown qop */
		      break;
		    }
	      }
	      break;

	    case CHALLENGE_STALE:
	      printf ("XXX stale: %s\n", value);
	      break;

	    case CHALLENGE_MAXBUF:
	      /* draft-ietf-sasl-rfc2831bis-02.txt:
	       * server_maxbuf ("maximal ciphertext buffer size")
	       * A number indicating the size of the largest buffer
	       * the server is able to receive when using "auth-int"
	       * or "auth-conf". The value MUST be bigger than 16 and
	       * smaller or equal to 16777215 (i.e.  2**24-1). If this
	       * directive is missing, the default value is
	       * 65536. This directive may appear at most once; if
	       * multiple instances are present, the client MUST abort
	       * the authentication exchange.
	       */
	      if (maxbuf != -1)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      maxbuf = strtol (value, NULL, 10);
	      if (maxbuf < MAXBUF_MIN || maxbuf > MAXBUF_MAX)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      break;

	    case CHALLENGE_CHARSET:
	      if (strcmp (DEFAULT_CHARSET, value) != 0)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      break;

	    case CHALLENGE_ALGORITHM:
	      if (strcmp (DEFAULT_ALGORITHM, value) != 0)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      break;

	    case CHALLENGE_CIPHER:
	      {
		char *subsubopts;
		char *val;

		if (state->cipher)
		  {
		    res = GSASL_MECHANISM_PARSE_ERROR;
		    goto done;
		  }

		subsubopts = value;
		while (*subsubopts != '\0')
		  switch (_gsasl_getsubopt (&subsubopts, cipher_opts, &val))
		    {
		    case CIPHER_DES_OPTION:
		      state->cipher |= GSASL_CIPHER_DES;
		      break;

		    case CIPHER_3DES_OPTION:
		      state->cipher |= GSASL_CIPHER_3DES;
		      break;

		    case CIPHER_RC4_OPTION:
		      state->cipher |= GSASL_CIPHER_RC4;
		      break;

		    case CIPHER_RC4_40_OPTION:
		      state->cipher |= GSASL_CIPHER_RC4_40;
		      break;

		    case CIPHER_RC4_56_OPTION:
		      state->cipher |= GSASL_CIPHER_RC4_56;
		      break;

		    case CIPHER_AES_OPTION:
		      state->cipher |= GSASL_CIPHER_AES;
		      break;

		    default:
		      /* Ignoring unknown cipher. */
		      break;
		    }
	      }
	      break;

	    default:
	      /* Ignoring unknown parameter. */
	      break;
	    }
	if (state->qop == 0 || state->nonce == NULL ||
	    (state->qop & GSASL_QOP_AUTH_CONF &&
	     !(state->cipher & GSASL_CIPHER_3DES)))
	  {
	    res = GSASL_MECHANISM_PARSE_ERROR;
	    goto done;
	  }

	if (cb_qop)
	  state->qop = cb_qop (sctx, state->qop);
	else
	  state->qop = GSASL_QOP_AUTH;

	if (maxbuf == -1)
	  maxbuf = MAXBUF_DEFAULT;

	if (cb_authorization_id)
	  {
	    size_t authzidlen;

	    res = cb_authorization_id (sctx, NULL, &authzidlen);
	    if (res != GSASL_OK)
	      goto done;
	    state->authzid = (char *) malloc (authzidlen + 1);
	    if (state->authzid == NULL)
	      {
		res = GSASL_MALLOC_ERROR;
		goto done;
	      }
	    res = cb_authorization_id (sctx, state->authzid, &authzidlen);
	    if (res != GSASL_OK)
	      goto done;
	    state->authzid[authzidlen] = '\0';
	  }
	/* username */
	{
	  size_t usernamelen;

	  res = cb_authentication_id (sctx, NULL, &usernamelen);
	  if (res != GSASL_OK)
	    goto done;

	  if (outlen +
	      strlen (USERNAME_PRE) +
	      usernamelen + strlen (USERNAME_POST) >= *output_len)
	    {
	      res = GSASL_TOO_SMALL_BUFFER;
	      goto done;
	    }

	  strcat (output, USERNAME_PRE);
	  outlen += strlen (USERNAME_PRE);

	  res = cb_authentication_id (sctx, &output[outlen], &usernamelen);
	  if (res != GSASL_OK)
	    goto done;
	  outlen += usernamelen;
	  output[outlen] = '\0';

	  strcat (output, USERNAME_POST);
	  outlen += strlen (USERNAME_POST);
	}
	/* realm */
	if (nrealm > 0)
	  {
	    if (outlen +
		strlen (REALM_PRE) +
		strlen (realm[0]) + strlen (REALM_POST) >= *output_len)
	      {
		res = GSASL_TOO_SMALL_BUFFER;
		goto done;
	      }

	    strcat (output, REALM_PRE);
	    outlen += strlen (REALM_PRE);

	    strcat (output, realm[0]);
	    outlen += strlen (realm[0]);

	    strcat (output, REALM_POST);
	    outlen += strlen (REALM_POST);
	  }
	/* nonce */
	{
	  if (outlen +
	      strlen (NONCE_PRE) +
	      strlen (state->nonce) + strlen (NONCE_POST) >= *output_len)
	    {
	      res = GSASL_TOO_SMALL_BUFFER;
	      goto done;
	    }

	  strcat (output, NONCE_PRE);
	  outlen += strlen (NONCE_PRE);

	  strcat (output, state->nonce);
	  outlen += strlen (state->nonce);

	  strcat (output, NONCE_POST);
	  outlen += strlen (NONCE_POST);
	}
	/* cnonce */
	{
	  if (outlen +
	      strlen (CNONCE_PRE) +
	      strlen (state->cnonce) + strlen (CNONCE_POST) >= *output_len)
	    {
	      res = GSASL_TOO_SMALL_BUFFER;
	      goto done;
	    }

	  strcat (output, CNONCE_PRE);
	  outlen += strlen (CNONCE_PRE);

	  strcat (output, state->cnonce);
	  outlen += strlen (state->cnonce);

	  strcat (output, CNONCE_POST);
	  outlen += strlen (CNONCE_POST);
	}
	/* nonce-count */
	{
	  if (outlen +
	      strlen (NONCE_COUNT_PRE) +
	      NCLEN + strlen (NONCE_COUNT_POST) >= *output_len)
	    {
	      res = GSASL_TOO_SMALL_BUFFER;
	      goto done;
	    }

	  strcat (output, NONCE_COUNT_PRE);
	  outlen += strlen (NONCE_COUNT_PRE);

	  sprintf (output + outlen, "%0*x", NCLEN, state->nc);
	  outlen += NCLEN;

	  strcat (output, NONCE_COUNT_POST);
	  outlen += strlen (NONCE_COUNT_POST);
	}
	/* qop */
	{
	  const char *qopstr;

	  if (state->qop & GSASL_QOP_AUTH_CONF)
	    qopstr = QOP_AUTH_CONF;
	  else if (state->qop & GSASL_QOP_AUTH_INT)
	    qopstr = QOP_AUTH_INT;
	  else			/* if (state->qop & GSASL_QOP_AUTH) */
	    qopstr = QOP_AUTH;

	  if (outlen +
	      strlen (QOP_PRE) +
	      strlen (qopstr) + strlen (QOP_POST) >= *output_len)
	    {
	      res = GSASL_TOO_SMALL_BUFFER;
	      goto done;
	    }

	  strcat (output, QOP_PRE);
	  outlen += strlen (QOP_PRE);

	  strcat (output, qopstr);
	  outlen += strlen (qopstr);

	  strcat (output, QOP_POST);
	  outlen += strlen (QOP_POST);
	}
	/* digest-uri */
	{
	  size_t servicelen = 0;
	  size_t hostnamelen = 0;
	  size_t servicenamelen = 0;
	  size_t len;

	  res = cb_service (sctx, NULL, &servicelen,
			    NULL, &hostnamelen, NULL, &servicenamelen);
	  if (res != GSASL_OK)
	    goto done;
	  len = servicelen + strlen ("/") + hostnamelen +
	    (servicenamelen > 0 ? strlen ("/") + servicenamelen : 0) + 1;
	  state->digesturi = malloc (len);
	  if (state->digesturi == NULL)
	    {
	      res = GSASL_MALLOC_ERROR;
	      goto done;
	    }
	  res = cb_service (sctx, state->digesturi, &servicelen,
			    state->digesturi + 1 + servicelen, &hostnamelen,
			    (servicenamelen > 0 ?
			     state->digesturi + 1 + servicelen + 1 +
			     hostnamelen : NULL), &servicenamelen);
	  if (res != GSASL_OK)
	    goto done;
	  state->digesturi[servicelen] = '/';
	  state->digesturi[servicelen + 1 + hostnamelen] = '/';
	  state->digesturi[len - 1] = '\0';

	  if (outlen +
	      strlen (DIGEST_URI_PRE) +
	      len + strlen (DIGEST_URI_POST) >= *output_len)
	    {
	      res = GSASL_TOO_SMALL_BUFFER;
	      goto done;
	    }

	  strcat (output, DIGEST_URI_PRE);
	  outlen += strlen (DIGEST_URI_PRE);

	  strcat (output, state->digesturi);
	  outlen += strlen (state->digesturi);

	  strcat (output, DIGEST_URI_POST);
	  outlen += strlen (DIGEST_URI_POST);
	}
	/* response */
	{
	  char *tmp;
	  size_t len;
	  char *secret, *p;
	  size_t secretlen;

	  if (outlen +
	      strlen (RESPONSE_PRE) +
	      RESPONSE_LENGTH + strlen (RESPONSE_POST) >= *output_len)
	    {
	      res = GSASL_TOO_SMALL_BUFFER;
	      goto done;
	    }

	  strcat (output, RESPONSE_PRE);
	  outlen += strlen (RESPONSE_PRE);

	  len = *output_len - outlen;
	  res = cb_authentication_id (sctx, output + outlen, &len);
	  if (res != GSASL_OK)
	    goto done;

	  secretlen = len + strlen (COLON);
	  if (nrealm > 0)
	    secretlen += strlen (realm[0]);
	  secretlen += strlen (COLON);

	  p = secret = malloc (secretlen);
	  if (secret == NULL)
	    {
	      res = GSASL_MALLOC_ERROR;
	      goto done;
	    }

	  memcpy (p, output + outlen, len);
	  p += len;
	  memcpy (p, COLON, strlen (COLON));
	  p += strlen (COLON);
	  if (nrealm > 0)
	    {
	      memcpy (p, realm[0], strlen (realm[0]));
	      p += strlen (realm[0]);
	    }
	  memcpy (p, COLON, strlen (COLON));
	  p += strlen (COLON);

	  len = *output_len - outlen;
	  /* XXX? password stored in callee's output buffer */
	  res = cb_password (sctx, output + outlen, &len);
	  if (res != GSASL_OK)
	    goto done;
	  tmp = gsasl_stringprep_nfkc (output + outlen, len);
	  if (tmp == NULL)
	    {
	      res = GSASL_UNICODE_NORMALIZATION_ERROR;
	      goto done;
	    }

	  secretlen += len;
	  p = secret = realloc (secret, secretlen);
	  if (secret == NULL)
	    {
	      res = GSASL_MALLOC_ERROR;
	      goto done;
	    }
	  p += secretlen - len;

	  memcpy (p, tmp, strlen (tmp));
	  free (tmp);

	  res = gsasl_md5 (secret, secretlen, (char **) &tmp);
	  if (res != GSASL_OK)
	    goto done;
	  memcpy (state->secret, tmp, MD5LEN);
	  free (tmp);

	  res = _gsasl_digest (state->response, state->secret,
			       state->nonce, state->nc, state->cnonce,
			       state->qop, state->authzid,
			       state->digesturi, A2_PRE,
			       state->cipher,
			       state->kic, state->kis,
			       state->kcc, state->kcs);
	  if (res != GSASL_OK)
	    goto done;
	  state->response[RESPONSE_LENGTH] = '\0';
	  memcpy (output + outlen, state->response, RESPONSE_LENGTH + 1);
	  outlen += RESPONSE_LENGTH;

	  strcat (output, RESPONSE_POST);
	  outlen += strlen (RESPONSE_POST);
	}
	if (cb_maxbuf)
	  maxbuf = cb_maxbuf (sctx, maxbuf);
	if (maxbuf >= MAXBUF_MIN &&
	    maxbuf != MAXBUF_DEFAULT && maxbuf <= MAXBUF_MAX)
	  {
	    char tmp[MAXBUF_MAX_DECIMAL_SIZE + 1];

	    sprintf (tmp, "%ld", maxbuf);

	    if (outlen + strlen (MAXBUF_PRE) + strlen (tmp) +
		strlen (MAXBUF_POST) >= *output_len)
	      {
		res = GSASL_TOO_SMALL_BUFFER;
		goto done;
	      }

	    strcat (output, MAXBUF_PRE);
	    outlen += strlen (MAXBUF_PRE);

	    strcat (output, tmp);
	    outlen += strlen (tmp);

	    strcat (output, MAXBUF_POST);
	    outlen += strlen (MAXBUF_POST);
	  }
	/* cipher */
	if (state->qop & GSASL_QOP_AUTH_CONF)
	  {
	    const char *cipherstr;

	    if (state->cipher & GSASL_CIPHER_AES)
	      cipherstr = CIPHER_AES;
	    else if (state->cipher & GSASL_CIPHER_3DES)
	      cipherstr = CIPHER_3DES;
	    else if (state->cipher & GSASL_CIPHER_DES)
	      cipherstr = CIPHER_DES;
	    else if (state->cipher & GSASL_CIPHER_RC4_56)
	      cipherstr = CIPHER_RC4_56;
	    else if (state->cipher & GSASL_CIPHER_RC4_40)
	      cipherstr = CIPHER_RC4_40;
	    else		/* if (state->cipher & GSASL_CIPHER_RC4) */
	      cipherstr = CIPHER_RC4;

	    if (outlen +
		strlen (CIPHER_PRE) +
		strlen (cipherstr) + strlen (CIPHER_POST) >= *output_len)
	      {
		res = GSASL_TOO_SMALL_BUFFER;
		goto done;
	      }

	    strcat (output, CIPHER_PRE);
	    outlen += strlen (CIPHER_PRE);

	    strcat (output, cipherstr);
	    outlen += strlen (cipherstr);

	    strcat (output, CIPHER_POST);
	    outlen += strlen (CIPHER_POST);
	  }
	/* authzid */
	if (state->authzid && strlen (state->authzid) > 0)
	  {
	    if (outlen +
		strlen (AUTHZID_PRE) +
		strlen (state->authzid) +
		strlen (AUTHZID_POST) >= *output_len)
	      {
		res = GSASL_TOO_SMALL_BUFFER;
		goto done;
	      }

	    strcat (output, AUTHZID_PRE);
	    outlen += strlen (AUTHZID_PRE);

	    strcat (output, state->authzid);
	    outlen += strlen (state->authzid);

	    strcat (output, AUTHZID_POST);
	    outlen += strlen (AUTHZID_POST);
	  }

	res = GSASL_NEEDS_MORE;
      done:
	if (realm)
	  free (realm);
	if (zinput)
	  free (zinput);
      }
      *output_len = outlen;
      state->step++;
      break;

    case 2:
      {
	char *zinput = NULL;

	if (input_len == 0)
	  {
	    *output_len = 0;
	    res = GSASL_MECHANISM_PARSE_ERROR;
	    break;
	  }

	if (input && input_len > 0)
	  {
	    zinput = malloc (input_len + 1);
	    if (zinput == NULL)
	      return GSASL_MALLOC_ERROR;
	    memcpy (zinput, input, input_len);
	    zinput[input_len] = '\0';
	  }

	res = GSASL_AUTHENTICATION_ERROR;
	subopts = zinput;
	while (*subopts != '\0')
	  switch (_gsasl_getsubopt (&subopts,
				    digest_responseauth_opts, &value))
	    {
	    case RESPONSEAUTH_RSPAUTH:
	      res = _gsasl_digest (output + outlen, state->secret,
				   state->nonce, state->nc,
				   state->cnonce, state->qop,
				   state->authzid, state->digesturi, COLON,
				   state->cipher, NULL, NULL, NULL, NULL);
	      if (res != GSASL_OK)
		break;

	      if (memcmp (value, output + outlen, RESPONSE_LENGTH) == 0)
		res = GSASL_OK;
	      else
		res = GSASL_AUTHENTICATION_ERROR;
	      break;

	    default:
	      /* Unknown suboption. */
	      break;
	    }
	free (zinput);
      }
      *output_len = 0;
      state->step++;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

#if CLIENT_PRINT_OUTPUT
  if (output && *output_len > 0)
    fprintf (stderr, "%s\n", output);
#endif

  if (res == GSASL_OK || res == GSASL_NEEDS_MORE)
    {
      *output2_len = *output_len;
      *output2 = malloc (*output2_len);
      if (!*output2)
	return GSASL_MALLOC_ERROR;
      memcpy (*output2, output, *output2_len);
    }

  return res;
}

void
_gsasl_digest_md5_client_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  _Gsasl_digest_md5_client_state *state = mech_data;

  if (state->authzid)
    free (state->authzid);
  if (state->nonce)
    free (state->nonce);
  if (state->digesturi)
    free (state->digesturi);
  free (state);
}

int
_gsasl_digest_md5_client_encode (Gsasl_session_ctx * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char **output, size_t * output_len)
{
  _Gsasl_digest_md5_client_state *state = mech_data;
  int res;

  if (state && state->step == 3)
    {
      res = digest_md5_encode (sctx, input, input_len, output, output_len,
			       state->qop, state->sendseqnum, state->kic);
      if (res != GSASL_OK)
	return res;

      state->sendseqnum++;
    }
  else
    {
      *output_len = input_len;
      *output = malloc (input_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, input, input_len);
    }

  return GSASL_OK;
}

int
_gsasl_digest_md5_client_decode (Gsasl_session_ctx * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char **output, size_t * output_len)
{
  _Gsasl_digest_md5_client_state *state = mech_data;
  int res;

  if (state && state->step == 3)
    {
      res = digest_md5_decode (sctx, input, input_len, output, output_len,
			       state->qop, state->readseqnum, state->kis);
      if (res != GSASL_OK)
	return res;

      state->readseqnum++;
    }
  else
    {
      *output_len = input_len;
      *output = malloc (input_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, input, input_len);
    }

  return GSASL_OK;
}
