/* digest-md5.c	--- Implementation of DIGEST-MD5 mechanism from RFC 2831.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 * Copyright (C) 1996, 1997, 1999 Free Software Foundation, Inc. (getsubopt)
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

/* Get strdup. */
#include "strdup.h"

#include <nettle-types.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#define HEXCHAR(c) ((c & 0x0F) > 9 ? 'a' + (c & 0x0F) - 10 : '0' + (c & 0x0F))

#define NONCE_ENTROPY_BITS  64
#define CNONCE_ENTROPY_BITS  64

#define DELIM ", "
#define REALM_PRE "realm=\""
#define REALM_POST "\"" DELIM
#define NONCE_PRE "nonce=\""
#define NONCE_POST "\"" DELIM
#define QOP_LIST_PRE "qop=\""
#define QOP_LIST_POST "\"" DELIM
#ifdef DONT_WORKAROUND_CYRUS_SASL_BUG
#define QOP_DELIM DELIM
#else
#define QOP_DELIM ","
#endif
#define QOP_AUTH "auth"
#define QOP_AUTH_INT "auth-int"
#define QOP_AUTH_CONF "auth-conf"
#define MAXBUF_PRE "maxbuf="
#define MAXBUF_POST DELIM
#define DEFAULT_CHARSET "utf-8"
#define CHARSET "charset=" DEFAULT_CHARSET DELIM
#define DEFAULT_ALGORITHM "md5-sess"
#define ALGORITHM "algorithm=" DEFAULT_ALGORITHM DELIM
#define CIPHER_PRE "cipher=\""
#define CIPHER_DELIM DELIM
#define CIPHER_DES "des"
#define CIPHER_3DES "3des"
#define CIPHER_RC4_40 "rc4-40"
#define CIPHER_RC4 "rc4"
#define CIPHER_RC4_56 "rc4-56"
#define CIPHER_AES "aes"
#ifdef DONT_WORKAROUND_CYRUS_SASL_BUG
#define CIPHER_POST "\"" DELIM
#else
#define CIPHER_POST "\""
#endif

#define USERNAME_PRE "username=\""
#define USERNAME_POST "\"" DELIM
#define CNONCE_PRE "cnonce=\""
#define CNONCE_POST "\"" DELIM
#define NONCE_COUNT_PRE "nc="
#define NONCE_COUNT_POST DELIM
#define QOP_PRE "qop="
#define QOP_POST DELIM
#define RESPONSE_PRE "response="
#define RESPONSE_POST "" DELIM
#define AUTHZID_PRE "authzid=\""
#define AUTHZID_POST "\"" DELIM
#define DIGEST_URI_PRE "digest-uri=\""
#define DIGEST_URI_POST "\"" DELIM

#define RSPAUTH_PRE "rspauth="
#define RSPAUTH_POST ""

#define A2_PRE "AUTHENTICATE:"
#define A2_POST ":00000000000000000000000000000000"
#define COLON ":"
#define NCLEN 8
#define MD5LEN 16
#define SASL_INTEGRITY_PREFIX_LENGTH 4
#define MACLEN 16
#define MAC_DATA_LEN 4
#define MAC_HMAC_LEN 10
#define MAC_MSG_TYPE "\x00\x01"
#define MAC_MSG_TYPE_LEN 2
#define MAC_SEQNUM_LEN 4
#define MAXBUF_MIN 17
#define MAXBUF_DEFAULT 65536
#define MAXBUF_MAX 16777215
#define MAXBUF_MAX_DECIMAL_SIZE 8
#define RESPONSE_LENGTH 32
#define RSPAUTH_LENGTH RESPONSE_LENGTH
#define DERIVE_CLIENT_INTEGRITY_KEY_STRING \
  "Digest session key to client-to-server signing key magic constant"
#define DERIVE_CLIENT_INTEGRITY_KEY_STRING_LEN 65
#define DERIVE_SERVER_INTEGRITY_KEY_STRING \
  "Digest session key to server-to-client signing key magic constant"
#define DERIVE_SERVER_INTEGRITY_KEY_STRING_LEN 65
#define DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING \
  "Digest H(A1) to client-to-server sealing key magic constant"
#define DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN 59
#define DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING \
  "Digest H(A1) to server-to-client sealing key magic constant"
#define DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING_LEN 59

/* MIN(a,b) returns the minimum of A and B.  */
#ifndef MIN
# define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#define CLIENT_PRINT_OUTPUT 0
#define SERVER_PRINT_OUTPUT 0

enum
{
  /* the order must match the following struct */
  CHALLENGE_REALM = 0,
  CHALLENGE_NONCE,
  CHALLENGE_QOP,
  CHALLENGE_STALE,
  CHALLENGE_MAXBUF,
  CHALLENGE_CHARSET,
  CHALLENGE_ALGORITHM,
  CHALLENGE_CIPHER
};

const char *digest_challenge_opts[] = {
  /* the order must match the previous enum */
  "realm",
  "nonce",
  "qop",
  "stale",
  "maxbuf",
  "charset",
  "algorithm",
  "cipher",
  NULL
};

enum
{
  /* the order must match the following struct */
  RESPONSE_USERNAME = 0,
  RESPONSE_REALM,
  RESPONSE_NONCE,
  RESPONSE_CNONCE,
  RESPONSE_NC,
  RESPONSE_QOP,
  RESPONSE_DIGEST_URI,
  RESPONSE_RESPONSE,
  RESPONSE_MAXBUF,
  RESPONSE_CHARSET,
  RESPONSE_CIPHER,
  RESPONSE_AUTHZID
};

const char *digest_response_opts[] = {
  /* the order must match the previous enum */
  "username",
  "realm",
  "nonce",
  "cnonce",
  "nc",
  "qop",
  "digest-uri",
  "response",
  "maxbuf",
  "charset",
  "cipher",
  "authzid",
  NULL
};

enum
{
  /* the order must match the following struct */
  RESPONSEAUTH_RSPAUTH = 0
};

const char *digest_responseauth_opts[] = {
  /* the order must match the previous enum */
  "rspauth",
  NULL
};

enum
{
  /* the order must match the following struct */
  QOP_AUTH_OPTION = 0,
  QOP_AUTH_INT_OPTION,
  QOP_AUTH_CONF_OPTION
};

const char *qop_opts[] = {
  /* the order must match the previous enum */
  QOP_AUTH,
  QOP_AUTH_INT,
  QOP_AUTH_CONF,
  NULL
};

enum
{
  /* the order must match the following struct */
  CIPHER_DES_OPTION = 0,
  CIPHER_3DES_OPTION,
  CIPHER_RC4_OPTION,
  CIPHER_RC4_40_OPTION,
  CIPHER_RC4_56_OPTION,
  CIPHER_AES_OPTION
};

const char *cipher_opts[] = {
  /* the order must match the previous enum */
  CIPHER_DES,
  CIPHER_3DES,
  CIPHER_RC4,
  CIPHER_RC4_40,
  CIPHER_RC4_56,
  CIPHER_AES,
  NULL
};

/* Parse comma separate list into words.
   Copyright (C) 1996, 1997, 1999 Free Software Foundation, Inc.
   From the GNU C Library, under GNU LGPL version 2.1.
   Contributed by Ulrich Drepper <drepper@cygnus.com>, 1996.
   Modified for Libgsasl by Simon Josefsson <simon@josefsson.org>
   Copyright (C) 2002  Simon Josefsson

   Parse comma separated suboption from *OPTIONP and match against
   strings in TOKENS.  If found return index and set *VALUEP to
   optional value introduced by an equal sign.  If the suboption is
   not part of TOKENS return in *VALUEP beginning of unknown
   suboption.  On exit *OPTIONP is set to the beginning of the next
   token or at the terminating NUL character.  */
static int
_gsasl_getsubopt (char **optionp, char *const *tokens, char **valuep)
{
  char *endp, *vstart;
  int cnt;
  int inside_quote = 0;

  if (**optionp == '\0')
    return -1;

  /* Find end of next token.  */
  endp = *optionp;
  while (*endp != '\0' && (inside_quote || (!inside_quote && *endp != ',')))
    {
      if (*endp == '"')
	inside_quote = !inside_quote;
      endp++;
    }

  /* Find start of value.  */
  vstart = memchr (*optionp, '=', endp - *optionp);
  if (vstart == NULL)
    vstart = endp;

  /* Try to match the characters between *OPTIONP and VSTART against
     one of the TOKENS.  */
  for (cnt = 0; tokens[cnt] != NULL; ++cnt)
    if (memcmp (*optionp, tokens[cnt], vstart - *optionp) == 0
	&& tokens[cnt][vstart - *optionp] == '\0')
      {
	/* We found the current option in TOKENS.  */
	*valuep = vstart != endp ? vstart + 1 : NULL;

	while (*valuep && (**valuep == ' ' ||
			   **valuep == '\t' ||
			   **valuep == '\r' ||
			   **valuep == '\n' || **valuep == '"'))
	  (*valuep)++;

	if (*endp != '\0')
	  {
	    *endp = '\0';
	    *optionp = endp + 1;
	  }
	else
	  *optionp = endp;
	endp--;
	while (*endp == ' ' ||
	       *endp == '\t' ||
	       *endp == '\r' || *endp == '\n' || *endp == '"')
	  *endp-- = '\0';
	while (**optionp == ' ' ||
	       **optionp == '\t' || **optionp == '\r' || **optionp == '\n')
	  (*optionp)++;

	return cnt;
      }

  /* The current suboption does not match any option.  */
  *valuep = *optionp;

  if (*endp != '\0')
    *endp++ = '\0';
  *optionp = endp;
  while (**optionp == ' ' ||
	 **optionp == '\t' || **optionp == '\r' || **optionp == '\n')
    (*optionp)++;

  return -1;
}

static int
_gsasl_digest (char *output,	/* must have 2*MD5LEN available bytes */
	       char secret[MD5LEN], char *nonce, uint32_t nc, char *cnonce, int qop, char *authzid, char *digesturi,
	       const char *a2string,	/* "AUTHENTICATE:" or ":" */
	       int cipher,	/* used by kcc and kcs */
	       char *kic,	/* output client integrity key, may be NULL */
	       char *kis,	/* output server integrity key, may be NULL */
	       char *kcc,	/* output client confidentiality key, may be NULL */
	       char *kcs)	/* output server confidentiality key, may be NULL */
{
  char nchex[NCLEN + 1];
  char a1hexhash[2 * MD5LEN];
  char a2hexhash[2 * MD5LEN];
  char *hash;
  char *tmp, *p;
  size_t tmplen;
  int rc;
  int i;

  /* A1 */

  tmplen = MD5LEN + strlen (COLON) + strlen (nonce) +
    strlen (COLON) + strlen (cnonce);
  if (authzid && strlen (authzid) > 0)
    tmplen += strlen (COLON) + strlen (authzid);

  p = tmp = malloc (tmplen);
  if (tmp == NULL)
    return GSASL_MALLOC_ERROR;

  memcpy (p, secret, MD5LEN);
  p += MD5LEN;
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, nonce, strlen (nonce));
  p += strlen (nonce);
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, cnonce, strlen (cnonce));
  p += strlen (cnonce);
  if (authzid && strlen (authzid) > 0)
    {
      memcpy (p, COLON, strlen (COLON));
      p += strlen (COLON);
      memcpy (p, authzid, strlen (authzid));
      p += strlen (authzid);
    }

  rc = gsasl_md5 (tmp, tmplen, (char **) &hash);
  free (tmp);
  if (rc != GSASL_OK)
    return rc;

  if (kic)
    {
      char *hash2;
      char tmp[MD5LEN + DERIVE_CLIENT_INTEGRITY_KEY_STRING_LEN];
      size_t tmplen = MD5LEN + DERIVE_CLIENT_INTEGRITY_KEY_STRING_LEN;

      memcpy (tmp, hash, MD5LEN);
      memcpy (tmp + MD5LEN, DERIVE_CLIENT_INTEGRITY_KEY_STRING,
	      DERIVE_CLIENT_INTEGRITY_KEY_STRING_LEN);

      rc = gsasl_md5 (tmp, tmplen, &hash2);
      if (rc != GSASL_OK)
	{
	  free (hash);
	  return rc;
	}

      memcpy (kic, hash2, MD5LEN);

      free (hash2);
    }

  if (kis)
    {
      char *hash2;
      char tmp[MD5LEN + DERIVE_SERVER_INTEGRITY_KEY_STRING_LEN];

      memcpy (tmp, hash, MD5LEN);
      memcpy (tmp + MD5LEN, DERIVE_SERVER_INTEGRITY_KEY_STRING,
	      DERIVE_SERVER_INTEGRITY_KEY_STRING_LEN);

      rc = gsasl_md5 (tmp,
		      MD5LEN + DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN,
		      &hash2);
      if (rc != GSASL_OK)
	{
	  free (hash);
	  return rc;
	}

      memcpy (kis, hash2, MD5LEN);

      free (hash2);
    }

  if (kcc)
    {
      char *hash2;
      int n;
      char tmp[MD5LEN + DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN];

      if (cipher == GSASL_CIPHER_RC4_40)
	n = 5;
      else if (cipher == GSASL_CIPHER_RC4_56)
	n = 7;
      else
	n = MD5LEN;

      memcpy (tmp, hash, n);
      memcpy (tmp + n, DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING,
	      DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN);

      rc = gsasl_md5 (tmp, n + DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN,
		      &hash2);
      if (rc != GSASL_OK)
	{
	  free (hash);
	  return rc;
	}

      memcpy (kcc, hash2, MD5LEN);

      free (hash2);
    }

  if (kcs)
    {
      char *hash2;
      int n;
      char tmp[MD5LEN + DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING_LEN];

      if (cipher == GSASL_CIPHER_RC4_40)
	n = 5;
      else if (cipher == GSASL_CIPHER_RC4_56)
	n = 7;
      else
	n = MD5LEN;

      memcpy (tmp, hash, n);
      memcpy (tmp + n, DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING,
	      DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING_LEN);

      rc = gsasl_md5 (tmp, n + DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING_LEN,
		      &hash2);
      if (rc != GSASL_OK)
	{
	  free (hash);
	  return rc;
	}

      memcpy (kcs, hash2, MD5LEN);

      free (hash2);
    }

  for (i = 0; i < MD5LEN; i++)
    {
      a1hexhash[2 * i + 1] = HEXCHAR (hash[i]);
      a1hexhash[2 * i + 0] = HEXCHAR (hash[i] >> 4);
    }

  free (hash);

  /* A2 */

  tmplen = strlen (a2string) + strlen (digesturi);
  if (qop & GSASL_QOP_AUTH_INT || qop & GSASL_QOP_AUTH_CONF)
    tmplen += strlen (A2_POST);

  p = tmp = malloc (tmplen);
  if (tmp == NULL)
    {
      free (hash);
      return GSASL_MALLOC_ERROR;
    }

  memcpy (p, a2string, strlen (a2string));
  p += strlen (a2string);
  memcpy (p, digesturi, strlen (digesturi));
  p += strlen (digesturi);
  if (qop & GSASL_QOP_AUTH_INT || qop & GSASL_QOP_AUTH_CONF)
    memcpy (p, A2_POST, strlen (A2_POST));

  rc = gsasl_md5 (tmp, tmplen, (char **) &hash);
  free (tmp);
  if (rc != GSASL_OK)
    return rc;

  for (i = 0; i < MD5LEN; i++)
    {
      a2hexhash[2 * i + 1] = HEXCHAR (hash[i]);
      a2hexhash[2 * i + 0] = HEXCHAR (hash[i] >> 4);
    }

  free (hash);

  /* response_value */

  sprintf (nchex, "%0*x", NCLEN, nc);

  tmplen = 2 * MD5LEN + strlen (COLON) + strlen (nonce) + strlen (COLON) +
    strlen (nchex) + strlen (COLON) + strlen (cnonce) + strlen (COLON);
  if (qop & GSASL_QOP_AUTH_CONF)
    tmplen += strlen (QOP_AUTH_CONF);
  else if (qop & GSASL_QOP_AUTH_INT)
    tmplen += strlen (QOP_AUTH_INT);
  else if (qop & GSASL_QOP_AUTH)
    tmplen += strlen (QOP_AUTH);
  tmplen += strlen (COLON) + 2 * MD5LEN;

  p = tmp = malloc (tmplen);
  if (tmp == NULL)
    return GSASL_MALLOC_ERROR;

  memcpy (p, a1hexhash, 2 * MD5LEN);
  p += 2 * MD5LEN;
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, nonce, strlen (nonce));
  p += strlen (nonce);
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, nchex, strlen (nchex));
  p += strlen (nchex);
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, cnonce, strlen (cnonce));
  p += strlen (cnonce);
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  if (qop & GSASL_QOP_AUTH_CONF)
    {
      memcpy (p, QOP_AUTH_CONF, strlen (QOP_AUTH_CONF));
      p += strlen (QOP_AUTH_CONF);
    }
  else if (qop & GSASL_QOP_AUTH_INT)
    {
      memcpy (p, QOP_AUTH_INT, strlen (QOP_AUTH_INT));
      p += strlen (QOP_AUTH_INT);
    }
  else if (qop & GSASL_QOP_AUTH)
    {
      memcpy (p, QOP_AUTH, strlen (QOP_AUTH));
      p += strlen (QOP_AUTH);
    }
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, a2hexhash, 2 * MD5LEN);

  rc = gsasl_md5 (tmp, tmplen, (char **) &hash);
  free (tmp);
  if (rc != GSASL_OK)
    return rc;

  for (i = 0; i < MD5LEN; i++)
    {
      output[2 * i + 1] = HEXCHAR (hash[i]);
      output[2 * i + 0] = HEXCHAR (hash[i] >> 4);
    }

  free (hash);

  return GSASL_OK;
}

/* Client */

#ifdef USE_CLIENT

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
			       char *output, size_t * output_len)
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

  return res;
}

int
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

  return GSASL_OK;
}

int
_gsasl_digest_md5_client_encode (Gsasl_session_ctx * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char *output, size_t * output_len)
{
  _Gsasl_digest_md5_client_state *state = mech_data;
  int res;

  if (state && state->step == 3 && state->qop & GSASL_QOP_AUTH_CONF)
    {
      /* XXX */
    }
  else if (state && state->step == 3 && state->qop & GSASL_QOP_AUTH_INT)
    {
      char *seqnumin;
      char *hash;
      uint32_t tmp;

      if (output &&
	  MAC_DATA_LEN + input_len + MAC_HMAC_LEN +
	  MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN > *output_len)
	return GSASL_TOO_SMALL_BUFFER;

      seqnumin = malloc (MAC_SEQNUM_LEN + input_len);
      if (seqnumin == NULL)
	return GSASL_MALLOC_ERROR;

      tmp = htonl (state->sendseqnum);
      memcpy (seqnumin, (char *) &tmp, MAC_SEQNUM_LEN);
      memcpy (seqnumin + MAC_SEQNUM_LEN, input, input_len);

      res = gsasl_hmac_md5 (state->kic, MD5LEN,
			    seqnumin, MAC_SEQNUM_LEN + input_len,
			    (char **) &hash);
      free (seqnumin);
      if (res != GSASL_OK || hash == NULL)
	return GSASL_CRYPTO_ERROR;

      if (output)
	{
	  *output_len = MAC_DATA_LEN;
	  memcpy (output + *output_len, input, input_len);
	  *output_len += input_len;
	  memcpy (output + *output_len, hash, MAC_HMAC_LEN);
	  *output_len += MAC_HMAC_LEN;
	  memcpy (output + *output_len, MAC_MSG_TYPE, MAC_MSG_TYPE_LEN);
	  *output_len += MAC_MSG_TYPE_LEN;
	  tmp = htonl (state->sendseqnum);
	  memcpy (output + *output_len, &tmp, MAC_SEQNUM_LEN);
	  *output_len += MAC_SEQNUM_LEN;
	  tmp = htonl (*output_len - MAC_DATA_LEN);
	  memcpy (output, &tmp, MAC_DATA_LEN);
	  state->sendseqnum++;
	}
      else
	*output_len = MAC_DATA_LEN + input_len + MAC_HMAC_LEN
	  + MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;

      free (hash);
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
_gsasl_digest_md5_client_decode (Gsasl_session_ctx * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char *output, size_t * output_len)
{
  _Gsasl_digest_md5_client_state *state = mech_data;

  if (state && state->step == 3 && state->qop & GSASL_QOP_AUTH_CONF)
    {
      /* XXX */
    }
  else if (state && state->step == 3 && state->qop & GSASL_QOP_AUTH_INT)
    {
      char *seqnumin;
      char *hash;
      uint32_t len, tmp;
      int res;

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH)
	return GSASL_NEEDS_MORE;

      len = ntohl (*(uint32_t *) input);

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH + len)
	return GSASL_NEEDS_MORE;

      len -= MAC_HMAC_LEN + MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;

      seqnumin = malloc (SASL_INTEGRITY_PREFIX_LENGTH + len);
      if (seqnumin == NULL)
	return GSASL_MALLOC_ERROR;

      tmp = htonl (state->readseqnum);

      memcpy (seqnumin, (char *) &tmp, SASL_INTEGRITY_PREFIX_LENGTH);
      memcpy (seqnumin + SASL_INTEGRITY_PREFIX_LENGTH,
	      input + MAC_DATA_LEN, len);

      res = gsasl_hmac_md5 (state->kis, MD5LEN,
			    seqnumin, MAC_SEQNUM_LEN + len, (char **) &hash);
      free (seqnumin);
      if (res != GSASL_OK || hash == NULL)
	return GSASL_CRYPTO_ERROR;

      if (memcmp
	  (hash,
	   input + input_len - MAC_SEQNUM_LEN - MAC_MSG_TYPE_LEN -
	   MAC_HMAC_LEN, MAC_HMAC_LEN) == 0
	  && memcmp (MAC_MSG_TYPE,
		     input + input_len - MAC_SEQNUM_LEN - MAC_MSG_TYPE_LEN,
		     MAC_MSG_TYPE_LEN) == 0
	  && memcmp (&tmp, input + input_len - MAC_SEQNUM_LEN,
		     MAC_SEQNUM_LEN) == 0)
	{
	  *output_len = len;
	  if (output)
	    {
	      memcpy (output, input + MAC_DATA_LEN, len);
	      state->readseqnum++;
	    }
	}
      else
	return GSASL_INTEGRITY_ERROR;

      free (hash);
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

#endif

/* Server */

#ifdef USE_SERVER

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
			       char *output, size_t * output_len)
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

  return res;
}

int
_gsasl_digest_md5_server_finish (Gsasl_session_ctx * sctx, void *mech_data)
{
  _Gsasl_digest_md5_server_state *state = mech_data;

  free (state);

  return GSASL_OK;
}

int
_gsasl_digest_md5_server_encode (Gsasl_session_ctx * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char *output, size_t * output_len)
{
  _Gsasl_digest_md5_server_state *state = mech_data;
  int res;

  if (state && state->step == 3 && state->qop & GSASL_QOP_AUTH_CONF)
    {
      /* XXX */
    }
  else if (state && state->step == 3 && state->qop & GSASL_QOP_AUTH_INT)
    {
      char *seqnumin;
      char *hash;
      uint32_t tmp;

      if (output &&
	  MAC_DATA_LEN + input_len + MAC_HMAC_LEN +
	  MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN > *output_len)
	return GSASL_TOO_SMALL_BUFFER;

      seqnumin = malloc (MAC_SEQNUM_LEN + input_len);
      if (seqnumin == NULL)
	return GSASL_MALLOC_ERROR;

      tmp = htonl (state->sendseqnum);
      memcpy (seqnumin, (char *) &tmp, MAC_SEQNUM_LEN);
      memcpy (seqnumin + MAC_SEQNUM_LEN, input, input_len);

      res = gsasl_hmac_md5 (state->kis, MD5LEN,
			    seqnumin, MAC_SEQNUM_LEN + input_len,
			    (char **) &hash);
      free (seqnumin);
      if (res != GSASL_OK || hash == NULL)
	return GSASL_CRYPTO_ERROR;

      if (output)
	{
	  *output_len = MAC_DATA_LEN;
	  memcpy (output + *output_len, input, input_len);
	  *output_len += input_len;
	  memcpy (output + *output_len, hash, MAC_HMAC_LEN);
	  *output_len += MAC_HMAC_LEN;
	  memcpy (output + *output_len, MAC_MSG_TYPE, MAC_MSG_TYPE_LEN);
	  *output_len += MAC_MSG_TYPE_LEN;
	  tmp = htonl (state->sendseqnum);
	  memcpy (output + *output_len, &tmp, MAC_SEQNUM_LEN);
	  *output_len += MAC_SEQNUM_LEN;
	  tmp = htonl (*output_len - MAC_DATA_LEN);
	  memcpy (output, &tmp, MAC_DATA_LEN);
	  state->sendseqnum++;
	}
      else
	*output_len = MAC_DATA_LEN + input_len + MAC_HMAC_LEN
	  + MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;

      free (hash);
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
_gsasl_digest_md5_server_decode (Gsasl_session_ctx * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char *output, size_t * output_len)
{
  _Gsasl_digest_md5_server_state *state = mech_data;

  if (state && state->step == 3 && state->qop & GSASL_QOP_AUTH_CONF)
    {
      /* XXX */
    }
  else if (state && state->step == 3 && state->qop & GSASL_QOP_AUTH_INT)
    {
      char *seqnumin;
      char *hash;
      uint32_t len, tmp;
      int res;

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH)
	return GSASL_NEEDS_MORE;

      len = ntohl (*(uint32_t *) input);

      if (input_len < SASL_INTEGRITY_PREFIX_LENGTH + len)
	return GSASL_NEEDS_MORE;

      len -= MAC_HMAC_LEN + MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;

      seqnumin = malloc (SASL_INTEGRITY_PREFIX_LENGTH + len);
      if (seqnumin == NULL)
	return GSASL_MALLOC_ERROR;

      tmp = htonl (state->readseqnum);

      memcpy (seqnumin, (char *) &tmp, SASL_INTEGRITY_PREFIX_LENGTH);
      memcpy (seqnumin + SASL_INTEGRITY_PREFIX_LENGTH,
	      input + MAC_DATA_LEN, len);

      res = gsasl_hmac_md5 (state->kic, MD5LEN,
			    seqnumin, MAC_SEQNUM_LEN + len, (char **) &hash);
      free (seqnumin);
      if (res != GSASL_OK || hash == NULL)
	return GSASL_CRYPTO_ERROR;

      if (memcmp
	  (hash,
	   input + input_len - MAC_SEQNUM_LEN - MAC_MSG_TYPE_LEN -
	   MAC_HMAC_LEN, MAC_HMAC_LEN) == 0
	  && memcmp (MAC_MSG_TYPE,
		     input + input_len - MAC_SEQNUM_LEN - MAC_MSG_TYPE_LEN,
		     MAC_MSG_TYPE_LEN) == 0
	  && memcmp (&tmp, input + input_len - MAC_SEQNUM_LEN,
		     MAC_SEQNUM_LEN) == 0)
	{
	  *output_len = len;
	  if (output)
	    {
	      memcpy (output, input + MAC_DATA_LEN, len);
	      state->readseqnum++;
	    }
	}
      else
	return GSASL_INTEGRITY_ERROR;

      free (hash);
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

#endif /* USE_SERVER */
