/* libgcrypt.c --- Crypto wrappers around libgcrypt.
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
 * You should have received a copy of the GNU Lesser General Public License
 * License along with GNU SASL Library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/* Note: This file is only built if GNU SASL uses Libgcrypt. */

#include "internal.h"

/* Get _gsasl_crypto_init. */
#include "crypto.h"

/* Get libgcrypt API. */
#include <gcrypt.h>

/* Refer to nettle.c for documentation. */

int
_gsasl_crypto_init (void)
{
  gcry_error_t err;

  err = gcry_control (GCRYCTL_ANY_INITIALIZATION_P);
  if (err == GPG_ERR_NO_ERROR)
    {
      if (gcry_check_version (GCRYPT_VERSION) == NULL)
	{
	  fprintf (stderr, "gcry_check_version(%s) failed: %s\n",
		   GCRYPT_VERSION, gcry_check_version (NULL));
	  return GSASL_CRYPTO_ERROR;
	}

      err = gcry_control (GCRYCTL_DISABLE_SECMEM, NULL, 0);
      if (err != GPG_ERR_NO_ERROR)
	{
	  fprintf (stderr, "gcry_control (GCRYCTL_DISABLE_SECMEM)"
		   " failed: %s\n", gcry_strerror (err));
	  return GSASL_CRYPTO_ERROR;
	}

      err = gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL, 0);
      if (err != GPG_ERR_NO_ERROR)
	{
	  fprintf (stderr, "gcry_control (GCRYCTL_INITIALIZATION_FINISHED)"
		   " failed: %s\n", gcry_strerror (err));
	  return GSASL_CRYPTO_ERROR;
	}
    }

  return GSASL_OK;
}

int
gsasl_randomize (char *data, size_t datalen)
{
  gcry_randomize ((unsigned char *) data, datalen, GCRY_VERY_STRONG_RANDOM);
  return GSASL_OK;
}

int
gsasl_nonce (char *data, size_t datalen)
{
  gcry_create_nonce ((unsigned char *) data, datalen);
  return GSASL_OK;
}

int
gsasl_md5 (const char *in, size_t inlen, char *out[16])
{
  size_t outlen = gcry_md_get_algo_dlen (GCRY_MD_MD5);
  gcry_md_hd_t hd;
  gpg_error_t err;
  unsigned char *p;

  err = gcry_md_open (&hd, GCRY_MD_MD5, 0);
  if (err != GPG_ERR_NO_ERROR)
    return GSASL_CRYPTO_ERROR;

  gcry_md_write (hd, in, inlen);

  p = gcry_md_read (hd, GCRY_MD_MD5);
  if (p == NULL)
    return GSASL_CRYPTO_ERROR;

  *out = malloc (outlen);
  if (!*out)
    return GSASL_MALLOC_ERROR;
  memcpy (*out, p, outlen);

  gcry_md_close (hd);

  return GSASL_OK;
}

int
gsasl_hmac_md5 (const char *key, size_t keylen,
		const char *in, size_t inlen, char *outhash[16])
{
  gcry_md_hd_t mdh;
  size_t hlen = gcry_md_get_algo_dlen (GCRY_MD_MD5);
  unsigned char *hash;
  gpg_error_t err;

  err = gcry_md_open (&mdh, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
  if (err != GPG_ERR_NO_ERROR)
    return GSASL_CRYPTO_ERROR;

  err = gcry_md_setkey (mdh, key, keylen);
  if (err != GPG_ERR_NO_ERROR)
    return GSASL_CRYPTO_ERROR;

  gcry_md_write (mdh, in, inlen);

  hash = gcry_md_read (mdh, GCRY_MD_MD5);
  if (hash == NULL)
    return GSASL_CRYPTO_ERROR;

  *outhash = malloc (hlen);
  if (!*outhash)
    return GSASL_MALLOC_ERROR;
  memcpy (*outhash, hash, hlen);

  gcry_md_close (mdh);

  return GSASL_OK;
}
