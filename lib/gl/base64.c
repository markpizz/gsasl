/* base64.c -- Encode binary data using printable characters.
   Copyright (C) 1999, 2000, 2001, 2004 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

/* Portions adapted from GNU MailUtils, by Simon Josefsson.  For more
   information, see RFC 3548 <http://www.ietf.org/rfc/rfc3548.txt>. */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* Get malloc. */
#include <stdlib.h>

/* Get size_overflow_p etc. */
#include "xsize.h"

/* Get prototype. */
#include "base64.h"

/* C89 compliant way to cast 'const char *' to 'const unsigned char *'. */
static inline const unsigned char *to_cucharp (const char *ch) { return ch; }

/* Base64 encode IN array of size INLEN into OUT array of size OUTLEN.
   If OUTLEN is less than BASE64_LENGTH(INLEN), write as many bytes as
   possible.  If OUTLEN is larger than BASE64_LENGTH(INLEN), also zero
   terminate the output buffer. */
void
base64_encode (const char *in, size_t inlen, char *out, size_t outlen)
{
  const char b64[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const unsigned char *iptr = to_cucharp (in);

  while (inlen && outlen)
    {
      *out++ = b64[iptr[0] >> 2];
      if (!--outlen)
	break;
      *out++ = b64[((iptr[0] << 4) + (--inlen ? (iptr[1] >> 4) : 0)) & 0x3f];
      if (!--outlen)
	break;
      *out++ =
	(inlen
	 ? b64[((iptr[1] << 2) + (--inlen ? (iptr[2] >> 6) : 0)) & 0x3f]
	 : '=');
      if (!--outlen)
	break;
      *out++ = inlen ? b64[iptr[2] & 0x3f] : '=';
      if (!--outlen)
	break;
      if (inlen)
	inlen--;
      iptr += 3;
    }

  if (outlen)
    *out = '\0';
}

/* Allocate a buffer and store zero terminated base64 encoded data
   from array IN of size INLEN, returning BASE64_LENGTH(INLEN), i.e.,
   the length of the encoded data, excluding the terminating zero.  On
   return, the OUT variable will hold a pointer to newly allocated
   memory that must be deallocated by the caller, or NULL on memory
   allocation failure.  If output length would overflow, SIZE_MAX is
   returned and OUT is undefined.  */
size_t
base64_encode_alloc (const char *in, size_t inlen, char **out)
{
  size_t outlen = xsum (1, xtimes (xmax (inlen, inlen + 2) / 3, 4));

  if (size_overflow_p (outlen))
    return SIZE_MAX;

  *out = malloc (outlen);
  if (*out)
    base64_encode (in, inlen, *out, outlen);

  return outlen - 1;
}

/* C89 compliant way to cast 'char *' to 'unsigned char *'. */
static inline unsigned char *to_ucharp (char *ch) { return ch; }

/* Decode base64 encoded input array IN of length INLEN to output
   array OUT that can hold *OUTLEN bytes.  Return true if decoding was
   successful, false otherwise.  If *OUTLEN is too small, as many
   bytes as possible will be written to OUT.  On return, *OUTLEN holds
   the length of decode bytes in OUT.  Note that if any non-alphabet
   characters are encountered, decoding is stopped and false is
   returned. */
bool
base64_decode (const char *in, size_t inlen, char *out, size_t * outlen)
{
  static const signed char b64[0x100] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -3, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
  };
  const unsigned char *iptr = to_cucharp (in);
  unsigned char *optr = to_ucharp (out);
  size_t len = *outlen;

  *outlen = 0;

  while (inlen >= 2)
    {
      if (!len--)
	return true;

      if (b64[iptr[0]] < 0 || b64[iptr[1]] < 0)
	return false;

      *optr++ = (b64[iptr[0]] << 2) | (b64[iptr[1]] >> 4);
      (*outlen)++;

      if (inlen == 2)
	return false;

      if (iptr[2] == '=')
	{
	  if (iptr[3] != '=')
	    return false;

	  if (inlen != 4)
	    return false;
	}
      else
	{
	  if (!len--)
	    return true;

	  if (b64[iptr[2]] < 0)
	    return false;

	  *optr++ = ((b64[iptr[1]] << 4) & 0xf0) | (b64[iptr[2]] >> 2);
	  (*outlen)++;

	  if (inlen == 3)
	    return false;

	  if (iptr[3] == '=')
	    {
	      if (inlen != 4)
		return false;
	    }
	  else
	    {
	      if (!len--)
		return true;

	      if (b64[iptr[3]] < 0)
		return false;

	      *optr++ = ((b64[iptr[2]] << 6) & 0xc0) | b64[iptr[3]];
	      (*outlen)++;
	    }
	}
      iptr += 4;
      inlen -= 4;
    }

  if (inlen != 0)
    return false;

  return true;

}

/* Allocate an output buffer OUT, and decode the base64 encoded data
   stored in IN of size INLEN.  On return, the actual size of the
   decoded data is stored in *OUTLEN.  The function return true if
   decoding was successful, or false on memory allocation, integer
   overflow or decoding errors.  */
bool
base64_decode_alloc (const char *in, size_t inlen, char **out,
		     size_t * outlen)
{

  size_t len = xtimes (inlen, 3);

  if (size_overflow_p (len))
    return false;

  *outlen = len / 4;	/* FIXME: May allocate one 1 or 2 bytes too
			   much, depending on input. */

  *out = malloc (*outlen);
  if (!*out)
    return false;

  return base64_decode (in, inlen, *out, outlen);
}
