/* nettle.c --- Crypto wrappers around nettle.
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

/* Note: This file is only built if GNU SASL uses Nettle. */

#include "internal.h"

/* For randomize. */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Get _gsasl_crypto_init. */
#include "crypto.h"

/* Get Nettle API. */
#include <hmac.h>

int
_gsasl_crypto_init (void)
{
  return GSASL_OK;
}

/**
 * gsasl_randomize:
 * @strong: 0 iff operation should not block, non-0 for very strong randomness.
 * @data: output array to be filled with random data.
 * @datalen: size of output array.
 *
 * Store cryptographically random data of given size in the provided
 * buffer.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_randomize (int strong, char *data, size_t datalen)
{
  int fd;
  char *device;
  size_t len = 0;
  int rc;

  if (strong)
    device = "/dev/random";
  else
    device = "/dev/urandom";

  fd = open (device, O_RDONLY);
  if (fd < 0)
    return GSASL_FOPEN_ERROR;

  do
    {
      ssize_t tmp;

      tmp = read (fd, data, datalen);

      if (tmp < 0)
	return GSASL_FOPEN_ERROR;

      len += tmp;
    }
  while (len < datalen);

  rc = close (fd);
  if (rc < 0)
    return GSASL_FCLOSE_ERROR;

  return GSASL_OK;
}

/**
 * gsasl_md5:
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @out: newly allocated character array with hash of data.
 *
 * Compute hash of data using MD5.  The @out buffer must be
 * deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_md5 (const char *in, size_t inlen, char *out[MD5_DIGEST_SIZE])
{
  struct md5_ctx md5;

  md5_init (&md5);
  md5_update (&md5, inlen, (uint8_t *) in);
  *out = malloc (MD5_DIGEST_SIZE);
  if (!*out)
    return GSASL_MALLOC_ERROR;
  md5_digest (&md5, MD5_DIGEST_SIZE, (uint8_t *) * out);

  return GSASL_OK;
}

/**
 * gsasl_hmac_md5:
 * @key: input character array with key to use.
 * @keylen: length of input character array with key to use.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: newly allocated character array with keyed hash of data.
 *
 * Compute keyed checksum of data using HMAC-MD5.  The @outhash buffer
 * must be deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_hmac_md5 (const char *key, size_t keylen,
		const char *in, size_t inlen, char *outhash[MD5_DIGEST_SIZE])
{
  struct hmac_md5_ctx ctx;

  hmac_md5_set_key (&ctx, keylen, (uint8_t *) key);
  hmac_md5_update (&ctx, inlen, (uint8_t *) in);
  *outhash = malloc (MD5_DIGEST_SIZE);
  if (!*outhash)
    return GSASL_MALLOC_ERROR;
  hmac_md5_digest (&ctx, MD5_DIGEST_SIZE, (uint8_t *) * outhash);

  return GSASL_OK;
}
