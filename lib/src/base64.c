/* base64.c --- Base64 encoding/decoding functions.
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

#include "internal.h"

#include "base64.h"

/* Get SIZE_MAX.  */
#include "xsize.h"

/**
 * gsasl_base64_to:
 * @in: input byte array
 * @inlen: size of input byte array
 * @out: pointer to newly allocated output byte array
 * @outlen: pointer to size of newly allocated output byte array
 *
 * Encode data as base64.  Converts characters, three at a time,
 * starting at src into four base64 characters in the target area
 * until the entire input buffer is encoded.
 *
 * Return value: Returns %GSASL_OK on success, or %GSASL_MALLOC_ERROR
 * if memory allocation fail or length overflow occurs.
 **/
int
gsasl_base64_to (const char *in, size_t inlen, char **out, size_t * outlen)
{
  size_t len = base64_encode_alloc (in, inlen, out);

  if (outlen)
    *outlen = len;

  if (len == SIZE_MAX || *out == NULL)
    return GSASL_MALLOC_ERROR;

  return GSASL_OK;
}

/**
 * gsasl_base64_from:
 * @in: input byte array
 * @inlen: size of input byte array
 * @out: pointer to newly allocated output byte array
 * @outlen: pointer to size of newly allocated output byte array
 *
 * Decode Base64 data.  Converts characters, four at a time, starting
 * at (or after) src from Base64 numbers into three 8 bit bytes in the
 * target area.
 *
 * Return value: Returns %GSASL_OK on success, or %GSASL_MALLOC_ERROR
 * on memory allocation errors, integer overflows, and (alas) invalid
 * input.
 **/
int
gsasl_base64_from (const char *in, size_t inlen, char **out, size_t * outlen)
{
  return base64_decode_alloc (in, inlen, out, outlen)
    ? GSASL_OK : GSASL_MALLOC_ERROR;
}
