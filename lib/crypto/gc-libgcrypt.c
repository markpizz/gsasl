/* gc-libgcrypt.c --- Crypto wrappers around libgcrypt for GC.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
 *
 * This file is part of GC.
 *
 * GC is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * GC is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License License along with GC; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

/* Note: This file is only built if GC uses Nettle. */

/* Get prototype. */
#include <gc.h>

/* Get libgcrypt API. */
#include <gcrypt.h>

/* Get fprintf. */
#include <stdio.h>
#include <assert.h>

/* Refer to nettle.c for documentation. */

int
gc_init (void)
{
  gcry_error_t err;

  err = gcry_control (GCRYCTL_ANY_INITIALIZATION_P);
  if (err == GPG_ERR_NO_ERROR)
    {
      if (gcry_check_version (GCRYPT_VERSION) == NULL)
	{
	  fprintf (stderr, "gcry_check_version(%s) failed: %s\n",
		   GCRYPT_VERSION, gcry_check_version (NULL));
	  return GC_INIT_ERROR;
	}

      err = gcry_control (GCRYCTL_DISABLE_SECMEM, NULL, 0);
      if (err != GPG_ERR_NO_ERROR)
	{
	  fprintf (stderr, "gcry_control (GCRYCTL_DISABLE_SECMEM)"
		   " failed: %s\n", gcry_strerror (err));
	  return GC_INIT_ERROR;
	}

      err = gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL, 0);
      if (err != GPG_ERR_NO_ERROR)
	{
	  fprintf (stderr, "gcry_control (GCRYCTL_INITIALIZATION_FINISHED)"
		   " failed: %s\n", gcry_strerror (err));
	  return GC_INIT_ERROR;
	}
    }

  return GC_OK;
}

int
gc_nonce (uint8_t *data, size_t datalen)
{
  gcry_create_nonce ((unsigned char *) data, datalen);
  return GC_OK;
}

int
gc_random (uint8_t *data, size_t datalen)
{
  gcry_randomize ((unsigned char *) data, datalen, GCRY_VERY_STRONG_RANDOM);
  return GC_OK;
}

int
gc_md5 (const uint8_t *in, size_t inlen, uint8_t out[GC_MD5_LEN])
{
  size_t outlen = gcry_md_get_algo_dlen (GCRY_MD_MD5);
  gcry_md_hd_t hd;
  gpg_error_t err;
  unsigned char *p;

  assert (outlen == GC_MD5_LEN);

  err = gcry_md_open (&hd, GCRY_MD_MD5, 0);
  if (err != GPG_ERR_NO_ERROR)
    return GC_MD5_ERROR;

  gcry_md_write (hd, in, inlen);

  p = gcry_md_read (hd, GCRY_MD_MD5);
  if (p == NULL)
    return GC_MD5_ERROR;

  memcpy (out, p, outlen);

  gcry_md_close (hd);

  return GC_OK;
}

int
gc_hmac_md5 (const uint8_t *key, size_t keylen,
	     const uint8_t *in, size_t inlen,
	     uint8_t outhash[GC_MD5_LEN])
{
  size_t hlen = gcry_md_get_algo_dlen (GCRY_MD_MD5);
  gcry_md_hd_t mdh;
  unsigned char *hash;
  gpg_error_t err;

  assert (hlen == GC_MD5_LEN);

  err = gcry_md_open (&mdh, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC);
  if (err != GPG_ERR_NO_ERROR)
    return GC_MD5_ERROR;

  err = gcry_md_setkey (mdh, key, keylen);
  if (err != GPG_ERR_NO_ERROR)
    return GC_MD5_ERROR;

  gcry_md_write (mdh, in, inlen);

  hash = gcry_md_read (mdh, GCRY_MD_MD5);
  if (hash == NULL)
    return GC_MD5_ERROR;

  memcpy (outhash, hash, hlen);

  gcry_md_close (mdh);

  return GC_OK;
}
