/* shared.c --- DIGEST-MD5 mechanism from RFC 2831, shared functions.
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

/* Get specification. */
#include "digest-md5.h"
#include "shared.h"

const char *const digest_challenge_opts[] = {
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

const char *const digest_response_opts[] = {
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

const char *const digest_responseauth_opts[] = {
  /* the order must match the previous enum */
  "rspauth",
  NULL
};

const char *const qop_opts[] = {
  /* the order must match the previous enum */
  QOP_AUTH,
  QOP_AUTH_INT,
  QOP_AUTH_CONF,
  NULL
};

const char *const cipher_opts[] = {
  /* the order must match the previous enum */
  CIPHER_DES,
  CIPHER_3DES,
  CIPHER_RC4,
  CIPHER_RC4_40,
  CIPHER_RC4_56,
  CIPHER_AES,
  NULL
};

int
_gsasl_digest (char *output,	/* must have 2*MD5LEN available bytes */
	       char secret[MD5LEN], char *nonce, uint32_t nc, char *cnonce, int qop, char *authzid, char *digesturi, const char *a2string,	/* "AUTHENTICATE:" or ":" */
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
