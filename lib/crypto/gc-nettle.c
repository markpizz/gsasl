/* gc-nettle.c --- Crypto wrappers around Nettle.
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

/* For randomize. */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Get Nettle API. */
#include <md5.h>
#include <hmac.h>

#if MD5_DIGEST_SIZE != GC_MD5_LEN
# error MD5 length mismatch
#endif

int
gc_init (void)
{
  return GC_OK;
}

static void
randomize (int strong, uint8_t *data, size_t datalen)
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
    return GC_RANDOM_ERROR;

  do
    {
      ssize_t tmp;

      tmp = read (fd, data, datalen);

      if (tmp < 0)
	return GC_RANDOM_ERROR;

      len += tmp;
    }
  while (len < datalen);

  rc = close (fd);
  if (rc < 0)
    return GC_RANDOM_ERROR;

  return GC_OK;
}

/**
 * gc_nonce:
 * @data: output array to be filled with unpredictable random data.
 * @datalen: size of output array.
 *
 * Store unpredictable data of given size in the provided buffer.
 *
 * Return value: Returns %GC_OK iff successful.
 **/
int
gc_nonce (uint8_t *data, size_t datalen)
{
  return randomize (0, data, datalen);
}

/**
 * gc_random:
 * @data: output array to be filled with strong random data.
 * @datalen: size of output array.
 *
 * Store cryptographically strong random data of given size in the
 * provided buffer.
 *
 * Return value: Returns %GC_OK iff successful.
 **/
int
gc_random (uint8_t *data, size_t datalen)
{
  return randomize (1, data, datalen);
}

/**
 * gc_md5:
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @out: newly allocated character array with hash of data.
 *
 * Compute hash of data using MD5.  The @out buffer must be
 * deallocated by the caller.
 *
 * Return value: Returns %GC_OK iff successful.
 **/
int
gc_md5 (const uint8_t *in, size_t inlen, uint8_t out[GC_MD5_LEN])
{
  struct md5_ctx md5;

  md5_init (&md5);
  md5_update (&md5, inlen, in);
  md5_digest (&md5, GC_MD5_LEN, out);

  return GC_OK;
}

/**
 * gc_hmac_md5:
 * @key: input character array with key to use.
 * @keylen: length of input character array with key to use.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: newly allocated character array with keyed hash of data.
 *
 * Compute keyed checksum of data using HMAC-MD5.  The @outhash buffer
 * must be deallocated by the caller.
 *
 * Return value: Returns %GC_OK iff successful.
 **/
int
gc_hmac_md5 (const uint8_t *key, size_t keylen,
	     const uint8_t *in, size_t inlen,
	     uint8_t outhash[GC_MD5_LEN])
{
  struct hmac_md5_ctx ctx;

  hmac_md5_set_key (&ctx, keylen, key);
  hmac_md5_update (&ctx, inlen, in);
  hmac_md5_digest (&ctx, GC_MD5_LEN, outhash);

  return GC_OK;
}
