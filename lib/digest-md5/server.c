/* server.c --- DIGEST-MD5 mechanism from RFC 2831, server side.
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

struct _Gsasl_digest_md5_server_state
{
  int step;
  char nonce[NONCE_ENTROPY_BITS / 8];
  Gsasl_qop qop;
  Gsasl_cipher cipher;
  uint32_t readseqnum, sendseqnum;
  char kic[MD5LEN];
  char kcc[MD5LEN];
  char kis[MD5LEN];
  char kcs[MD5LEN];
};
typedef struct _Gsasl_digest_md5_server_state _Gsasl_digest_md5_server_state;

int
_gsasl_digest_md5_server_start (Gsasl_session_ctx * sctx, void **mech_data)
{
  _Gsasl_digest_md5_server_state *state;
  Gsasl_server_callback_retrieve cb_retrieve;
  Gsasl_server_callback_digest_md5 cb_digest_md5;
  Gsasl_ctx *ctx;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_retrieve = gsasl_server_callback_retrieve_get (ctx);
  cb_digest_md5 = gsasl_server_callback_digest_md5_get (ctx);

  if (gsasl_server_callback_digest_md5_get (ctx) == NULL &&
      gsasl_server_callback_retrieve_get (ctx) == NULL)
    return GSASL_NEED_SERVER_DIGEST_MD5_CALLBACK;

  state = (_Gsasl_digest_md5_server_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;
  state->qop = GSASL_QOP_AUTH | GSASL_QOP_AUTH_INT | GSASL_QOP_AUTH_CONF;
  state->cipher = GSASL_CIPHER_DES | GSASL_CIPHER_3DES | GSASL_CIPHER_RC4 |
    GSASL_CIPHER_RC4_40 | GSASL_CIPHER_RC4_56 | GSASL_CIPHER_AES;
  gsasl_nonce (state->nonce, NONCE_ENTROPY_BITS / 8);
  state->readseqnum = 0;
  state->sendseqnum = 0;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_digest_md5_server_step (Gsasl_session_ctx * sctx,
			       void *mech_data,
			       const char *input,
			       size_t input_len,
			       char **output2, size_t * output2_len)
{
  _Gsasl_digest_md5_server_state *state = mech_data;
  Gsasl_server_callback_realm cb_realm;
  Gsasl_server_callback_qop cb_qop;
  Gsasl_server_callback_maxbuf cb_maxbuf;
  Gsasl_server_callback_cipher cb_cipher;
  Gsasl_server_callback_retrieve cb_retrieve;
  Gsasl_server_callback_digest_md5 cb_digest_md5;
  Gsasl_ctx *ctx;
  int res;
  int outlen;
  unsigned long maxbuf = MAXBUF_DEFAULT;
  /* FIXME: Remove fixed size buffer. */
  char output[BUFSIZ];
  size_t outputlen = BUFSIZ - 1;
  size_t *output_len = &outputlen;

  *output2 = NULL;
  *output2_len = 0;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_realm = gsasl_server_callback_realm_get (ctx);
  cb_qop = gsasl_server_callback_qop_get (ctx);
  cb_maxbuf = gsasl_server_callback_maxbuf_get (ctx);
  cb_cipher = gsasl_server_callback_cipher_get (ctx);
  cb_retrieve = gsasl_server_callback_retrieve_get (ctx);
  cb_digest_md5 = gsasl_server_callback_digest_md5_get (ctx);

  if (gsasl_server_callback_digest_md5_get (ctx) == NULL &&
      gsasl_server_callback_retrieve_get (ctx) == NULL)
    return GSASL_NEED_SERVER_DIGEST_MD5_CALLBACK;

  if (*output_len < 1)
    return GSASL_TOO_SMALL_BUFFER;

  strcpy (output, "");
  outlen = 0;

#if SERVER_PRINT_OUTPUT
  if (input && input_len > 0)
    fprintf (stderr, "%s\n", input);
#endif

  switch (state->step)
    {
    case 0:
      if (cb_realm)
	{
	  int i;
	  size_t realmlen;

	  realmlen = *output_len;
	  for (i = 0; cb_realm (sctx, NULL, &realmlen, i) == GSASL_OK; i++)
	    {
	      if (outlen + strlen (REALM_PRE) +
		  realmlen + strlen (REALM_POST) >= *output_len)
		return GSASL_TOO_SMALL_BUFFER;

	      strcat (output, REALM_PRE);
	      outlen += strlen (REALM_PRE);

	      cb_realm (sctx, &output[outlen], &realmlen, i);
	      outlen += realmlen;
	      output[outlen] = '\0';

	      strcat (output, REALM_POST);
	      outlen += strlen (REALM_POST);

	      realmlen = *output_len - outlen;
	    }
	}
      /* nonce */
      {
	int i;

	if (outlen + strlen (NONCE_PRE) +
	    2 * NONCE_ENTROPY_BITS / 8 + strlen (NONCE_POST) >= *output_len)
	  return GSASL_TOO_SMALL_BUFFER;

	strcat (output, NONCE_PRE);
	outlen += strlen (NONCE_PRE);

	for (i = 0; i < NONCE_ENTROPY_BITS / 8; i++)
	  {
	    output[outlen + 2 * i + 1] = HEXCHAR (state->nonce[i]);
	    output[outlen + 2 * i + 0] = HEXCHAR (state->nonce[i] >> 4);
	  }
	output[outlen + 2 * NONCE_ENTROPY_BITS / 8] = '\0';
	outlen += 2 * NONCE_ENTROPY_BITS / 8;

	strcat (output, NONCE_POST);
	outlen += strlen (NONCE_POST);
      }
      /* qop */
      {
	if (outlen +
	    strlen (QOP_LIST_PRE) +
	    strlen (QOP_AUTH) +
	    strlen (QOP_AUTH_INT) +
	    strlen (QOP_AUTH_CONF) + strlen (QOP_LIST_POST) >= *output_len)
	  return GSASL_TOO_SMALL_BUFFER;

	if (cb_qop)
	  state->qop = cb_qop (sctx);

	if (state->qop &
	    (GSASL_QOP_AUTH | GSASL_QOP_AUTH_INT | GSASL_QOP_AUTH_CONF))
	  {
	    strcat (output, QOP_LIST_PRE);
	    outlen += strlen (QOP_LIST_PRE);
	  }

	if (state->qop & GSASL_QOP_AUTH)
	  {
	    strcat (output, QOP_AUTH);
	    outlen += strlen (QOP_AUTH);

	    strcat (output, QOP_DELIM);
	    outlen += strlen (QOP_DELIM);
	  }

	if (state->qop & GSASL_QOP_AUTH_INT)
	  {
	    strcat (output, QOP_AUTH_INT);
	    outlen += strlen (QOP_AUTH_INT);

	    strcat (output, QOP_DELIM);
	    outlen += strlen (QOP_DELIM);
	  }

	if (state->qop & GSASL_QOP_AUTH_CONF)
	  {
	    strcat (output, QOP_AUTH_CONF);
	    outlen += strlen (QOP_AUTH_CONF);
	  }

	if (state->qop &
	    (GSASL_QOP_AUTH | GSASL_QOP_AUTH_INT | GSASL_QOP_AUTH_CONF))
	  {
	    strcat (output, QOP_LIST_POST);
	    outlen += strlen (QOP_LIST_POST);
	  }
      }
      /* maxbuf */
      if (cb_maxbuf)
	maxbuf = cb_maxbuf (sctx);
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
      /* charset */
      {
	if (outlen + strlen (CHARSET) >= *output_len)
	  return GSASL_TOO_SMALL_BUFFER;

	strcat (output, CHARSET);
	outlen += strlen (CHARSET);
      }
      /* algorithm */
      {
	if (outlen + strlen (ALGORITHM) >= *output_len)
	  return GSASL_TOO_SMALL_BUFFER;

	strcat (output, ALGORITHM);
	outlen += strlen (ALGORITHM);
      }
      /* cipher */
      {
	if (outlen +
	    strlen (CIPHER_PRE) +
	    strlen (CIPHER_DES) +
	    strlen (CIPHER_DELIM) +
	    strlen (CIPHER_3DES) +
	    strlen (CIPHER_DELIM) +
	    strlen (CIPHER_RC4) +
	    strlen (CIPHER_DELIM) +
	    strlen (CIPHER_RC4_40) +
	    strlen (CIPHER_DELIM) +
	    strlen (CIPHER_RC4_56) +
	    strlen (CIPHER_DELIM) +
	    strlen (CIPHER_AES) +
	    strlen (CIPHER_DELIM) + strlen (CIPHER_POST) >= *output_len)
	  return GSASL_TOO_SMALL_BUFFER;

	if (cb_cipher)
	  state->cipher = cb_cipher (sctx);

	strcat (output, CIPHER_PRE);
	outlen += strlen (CIPHER_PRE);

	if (state->cipher & GSASL_CIPHER_DES)
	  {
	    strcat (output, CIPHER_DES);
	    outlen += strlen (CIPHER_DES);

	    strcat (output, CIPHER_DELIM);
	    outlen += strlen (CIPHER_DELIM);
	  }

	if (state->cipher & GSASL_CIPHER_3DES)
	  {
	    strcat (output, CIPHER_3DES);
	    outlen += strlen (CIPHER_3DES);

	    strcat (output, CIPHER_DELIM);
	    outlen += strlen (CIPHER_DELIM);
	  }

	if (state->cipher & GSASL_CIPHER_RC4)
	  {
	    strcat (output, CIPHER_RC4);
	    outlen += strlen (CIPHER_RC4);

	    strcat (output, CIPHER_DELIM);
	    outlen += strlen (CIPHER_DELIM);
	  }

	if (state->cipher & GSASL_CIPHER_RC4_40)
	  {
	    strcat (output, CIPHER_RC4_40);
	    outlen += strlen (CIPHER_RC4_40);

	    strcat (output, CIPHER_DELIM);
	    outlen += strlen (CIPHER_DELIM);
	  }

	if (state->cipher & GSASL_CIPHER_RC4_56)
	  {
	    strcat (output, CIPHER_RC4_56);
	    outlen += strlen (CIPHER_RC4_56);

	    strcat (output, CIPHER_DELIM);
	    outlen += strlen (CIPHER_DELIM);
	  }

	if (state->cipher & GSASL_CIPHER_AES)
	  {
	    strcat (output, CIPHER_AES);
	    outlen += strlen (CIPHER_AES);

	    strcat (output, CIPHER_DELIM);
	    outlen += strlen (CIPHER_DELIM);
	  }

	strcat (output, CIPHER_POST);
	outlen += strlen (CIPHER_POST);
      }
      *output_len = outlen;
      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 1:
      {
	char *nonce = NULL;
	char *cnonce = NULL;
	uint32_t nc = 0;
	char *authzid = NULL;
	char *digesturi = NULL;
	const char *subopts, *value;
	char *realm = NULL;
	char *username = NULL;
	char *response = NULL;
	char *zinput = NULL;
	Gsasl_qop qop = 0;
	long maxbuf = -1;
	int cipher = 0;
	int i;
	char secret[MD5LEN];

	if (input_len == 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (input && input_len > 0)
	  {
	    zinput = malloc (input_len + 1);
	    if (zinput == NULL)
	      return GSASL_MALLOC_ERROR;
	    memcpy (zinput, input, input_len);
	    zinput[input_len] = '\0';
	  }

	subopts = zinput;
	while (*subopts != '\0')
	  switch (_gsasl_getsubopt (&subopts, digest_response_opts, &value))
	    {
	    case RESPONSE_USERNAME:
	      if (username != NULL)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      username = strdup (value);
	      break;

	    case RESPONSE_REALM:
	      if (realm != NULL)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      realm = strdup (value);
	      break;

	    case RESPONSE_NONCE:
	      if (nonce != NULL)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      nonce = strdup (value);
	      res = GSASL_OK;
	      for (i = 0; i < MIN (strlen (nonce), NONCE_ENTROPY_BITS / 8);
		   i++)
		if ((nonce[2 * i + 1] != HEXCHAR (state->nonce[i]))
		    || (nonce[2 * i + 0] != HEXCHAR (state->nonce[i] >> 4)))
		  res = GSASL_MECHANISM_PARSE_ERROR;
	      if (res != GSASL_OK)
		goto done;
	      break;

	    case RESPONSE_CNONCE:
	      if (cnonce != NULL)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      cnonce = strdup (value);
	      break;

	    case RESPONSE_NC:
	      if (nc != 0)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      nc = strtoul (value, NULL, 16);
	      break;

	    case RESPONSE_QOP:
	      if (strcmp (value, QOP_AUTH) == 0)
		qop = GSASL_QOP_AUTH;
	      else if (strcmp (value, QOP_AUTH_INT) == 0)
		qop = GSASL_QOP_AUTH_INT;
	      else if (strcmp (value, QOP_AUTH_CONF) == 0)
		qop = GSASL_QOP_AUTH_CONF;
	      else
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      if (!(state->qop & qop))
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      state->qop = qop;
	      break;

	    case RESPONSE_DIGEST_URI:
	      if (digesturi != NULL)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      digesturi = strdup (value);
	      break;

	    case RESPONSE_RESPONSE:
	      if (response != NULL)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      response = strdup (value);
	      break;

	    case RESPONSE_MAXBUF:
	      /* draft-ietf-sasl-rfc2831bis-02.txt:
	       *
	       * client_maxbuf: A number indicating the size of the
	       * largest ciphertext buffer the client is able to
	       * receive when using "auth-int" or "auth-conf". If this
	       * directive is missing, the default value is
	       * 65536. This directive may appear at most once; if
	       * multiple instances are present, the server MUST abort
	       * the authentication exchange. If the value is less or
	       * equal to 16 or bigger than 16777215 (i.e.  2**24-1),
	       * the server MUST abort the authentication exchange.
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

	    case RESPONSE_CHARSET:
	      if (strcmp (DEFAULT_CHARSET, value) != 0)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      break;

	    case RESPONSE_CIPHER:
	      if (cipher != 0)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      if (strcmp (value, CIPHER_AES) == 0)
		cipher = GSASL_CIPHER_AES;
	      else if (strcmp (value, CIPHER_3DES) == 0)
		cipher = GSASL_CIPHER_3DES;
	      else if (strcmp (value, CIPHER_DES) == 0)
		cipher = GSASL_CIPHER_DES;
	      else if (strcmp (value, CIPHER_RC4) == 0)
		cipher = GSASL_CIPHER_RC4;
	      else if (strcmp (value, CIPHER_RC4_40) == 0)
		cipher = GSASL_CIPHER_RC4_40;
	      else if (strcmp (value, CIPHER_RC4_56) == 0)
		cipher = GSASL_CIPHER_RC4_56;
	      else
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      if (!(state->cipher & cipher))
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      state->cipher = cipher;
	      break;

	    case RESPONSE_AUTHZID:
	      if (authzid != NULL)
		{
		  res = GSASL_MECHANISM_PARSE_ERROR;
		  goto done;
		}
	      authzid = strdup (value);
	      break;

	    default:
	      /* Ignoring unknown parameter. */
	      break;
	    }

	if (username == NULL || nonce == NULL ||
	    cnonce == NULL || response == NULL ||
	    (state->qop & GSASL_QOP_AUTH_CONF && state->cipher == 0))
	  {
	    res = GSASL_MECHANISM_PARSE_ERROR;
	    goto done;
	  }

	if (maxbuf == -1)
	  maxbuf = MAXBUF_DEFAULT;

	if (outlen +
	    strlen (RSPAUTH_PRE) +
	    RESPONSE_LENGTH + strlen (RSPAUTH_POST) >= *output_len)
	  {
	    res = GSASL_TOO_SMALL_BUFFER;
	    goto done;
	  }
	if (cb_retrieve)
	  {
	    char *tmp;
	    size_t keylen;
	    char *key;
	    char *normkey;

	    res = cb_retrieve (sctx, username, authzid, realm, NULL, &keylen);
	    if (res != GSASL_OK)
	      goto done;
	    key = malloc (keylen);
	    if (key == NULL)
	      {
		res = GSASL_MALLOC_ERROR;
		goto done;
	      }
	    res = cb_retrieve (sctx, username, authzid, realm, key, &keylen);
	    if (res != GSASL_OK)
	      {
		free (key);
		goto done;
	      }
	    normkey = gsasl_stringprep_nfkc (key, keylen);
	    free (key);
	    if (normkey == NULL)
	      {
		res = GSASL_UNICODE_NORMALIZATION_ERROR;
		goto done;
	      }

	    {
	      char *hin;
	      size_t hinlen;
	      char *p;

	      hinlen = strlen (username) + strlen (COLON);
	      if (realm)
		hinlen += strlen (realm);
	      hinlen += strlen (COLON) + strlen (normkey);

	      p = hin = malloc (hinlen);
	      if (hin == NULL)
		{
		  res = GSASL_MALLOC_ERROR;
		  goto done;
		}

	      memcpy (p, username, strlen (username));
	      p += strlen (username);
	      memcpy (p, COLON, strlen (COLON));
	      p += strlen (COLON);
	      if (realm)
		{
		  memcpy (p, realm, strlen (realm));
		  p += strlen (realm);
		}
	      memcpy (p, COLON, strlen (COLON));
	      p += strlen (COLON);
	      memcpy (p, normkey, strlen (normkey));
	      p += strlen (normkey);

	      res = gsasl_md5 (hin, hinlen, (char **) &tmp);
	      free (hin);
	      if (res != GSASL_OK)
		goto done;
	      memcpy (secret, tmp, MD5LEN);
	      free (tmp);
	    }
	  }
	else			/* if (cb_digest_md5) */
	  {
	    /* XXX? secret hash stored in callee's output buffer */
	    res = cb_digest_md5 (sctx, username, realm, output + outlen);
	    if (res != GSASL_OK)
	      goto done;

	    memcpy (secret, output + outlen, MD5LEN);
	  }

	/* verify response */
	res = _gsasl_digest (output + outlen, secret,
			     nonce, nc, cnonce, state->qop, authzid,
			     digesturi, A2_PRE,
			     state->cipher, NULL, NULL, NULL, NULL);
	if (res != GSASL_OK)
	  goto done;

	if (memcmp (response, output + outlen, RESPONSE_LENGTH) != 0)
	  {
	    res = GSASL_AUTHENTICATION_ERROR;
	    goto done;
	  }

	output[outlen] = '\0';

	/* XXX check more things here.  digest-uri?,
	   nc etc.  nonce, which is the most important, is checked
	   above. */

	/* generate rspauth */

	strcat (output, RSPAUTH_PRE);
	outlen += strlen (RSPAUTH_PRE);

	res = _gsasl_digest (output + outlen, secret,
			     nonce, nc, cnonce, state->qop, authzid,
			     digesturi, COLON,
			     state->cipher,
			     state->kic, state->kis, state->kcc, state->kcs);
	if (res != GSASL_OK)
	  goto done;
	outlen += RSPAUTH_LENGTH;
	output[outlen] = '\0';

	strcat (output, RSPAUTH_POST);
	outlen += strlen (RSPAUTH_POST);

	res = GSASL_NEEDS_MORE;
      done:
	if (username)
	  free (username);
	if (authzid)
	  free (authzid);
	if (response)
	  free (response);
	if (digesturi)
	  free (digesturi);
	if (nonce)
	  free (nonce);
	if (cnonce)
	  free (cnonce);
	if (realm)
	  free (realm);
	if (zinput)
	  free (zinput);
      }
      *output_len = outlen;
      state->step++;
      break;

    case 2:
      *output_len = 0;
      state->step++;
      res = GSASL_OK;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

#if SERVER_PRINT_OUTPUT
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
_gsasl_digest_md5_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  _Gsasl_digest_md5_server_state *state = mech_data;

  free (state);
}

int
_gsasl_digest_md5_server_encode (Gsasl_session_ctx * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char **output, size_t * output_len)
{
  _Gsasl_digest_md5_server_state *state = mech_data;
  int res;

  if (state && state->step == 3)
    {
      res = digest_md5_encode (sctx, input, input_len, output, output_len,
			       state->qop, state->sendseqnum, state->kis);
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
_gsasl_digest_md5_server_decode (Gsasl_session_ctx * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char **output, size_t * output_len)
{
  _Gsasl_digest_md5_server_state *state = mech_data;
  int res;

  if (state && state->step == 3)
    {
      res = digest_md5_decode (sctx, input, input_len, output, output_len,
			       state->qop, state->readseqnum, state->kic);
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
