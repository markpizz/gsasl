/* session.c --- Data integrity/privacy protection of DIGEST-MD5.
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

/* Get gsasl.h and other stuff. */
#include "shared.h"

/* Get specification. */
#include "session.h"

int
digest_md5_encode (Gsasl_session_ctx * sctx,
		   const char *input, size_t input_len,
		   char **output, size_t * output_len,
		   Gsasl_qop qop,
		   uint32_t sendseqnum,
		   char key[MD5LEN])
{
  int res;

  if (qop & GSASL_QOP_AUTH_CONF)
    {
      return GSASL_INTEGRITY_ERROR;
    }
  else if (qop & GSASL_QOP_AUTH_INT)
    {
      char *seqnumin;
      char *hash;
      uint32_t tmp;
      size_t len;

      seqnumin = malloc (MAC_SEQNUM_LEN + input_len);
      if (seqnumin == NULL)
	return GSASL_MALLOC_ERROR;

      tmp = htonl (sendseqnum);
      memcpy (seqnumin, (char *) &tmp, MAC_SEQNUM_LEN);
      memcpy (seqnumin + MAC_SEQNUM_LEN, input, input_len);

      res = gsasl_hmac_md5 (key, MD5LEN,
			    seqnumin, MAC_SEQNUM_LEN + input_len,
			    (char **) &hash);
      free (seqnumin);
      if (res != GSASL_OK || hash == NULL)
	return GSASL_CRYPTO_ERROR;

      *output_len = MAC_DATA_LEN + input_len + MAC_HMAC_LEN +
	MAC_MSG_TYPE_LEN + MAC_SEQNUM_LEN;
      *output = malloc (*output_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;

      len = MAC_DATA_LEN;
      memcpy (*output + len, input, input_len);
      len += input_len;
      memcpy (*output + len, hash, MAC_HMAC_LEN);
      len += MAC_HMAC_LEN;
      memcpy (*output + len, MAC_MSG_TYPE, MAC_MSG_TYPE_LEN);
      len += MAC_MSG_TYPE_LEN;
      tmp = htonl (sendseqnum);
      memcpy (*output + len, &tmp, MAC_SEQNUM_LEN);
      len += MAC_SEQNUM_LEN;
      tmp = htonl (len - MAC_DATA_LEN);
      memcpy (*output, &tmp, MAC_DATA_LEN);

      free (hash);
    }

  return GSASL_OK;
}

int
digest_md5_decode (Gsasl_session_ctx * sctx,
		   const char *input,
		   size_t input_len,
		   char **output, size_t * output_len,
		   Gsasl_qop qop,
		   uint32_t readseqnum,
		   char key[MD5LEN])
{
  if (qop & GSASL_QOP_AUTH_CONF)
    {
      return GSASL_INTEGRITY_ERROR;
    }
  else if (qop & GSASL_QOP_AUTH_INT)
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

      tmp = htonl (readseqnum);

      memcpy (seqnumin, (char *) &tmp, SASL_INTEGRITY_PREFIX_LENGTH);
      memcpy (seqnumin + SASL_INTEGRITY_PREFIX_LENGTH,
	      input + MAC_DATA_LEN, len);

      res = gsasl_hmac_md5 (key, MD5LEN, seqnumin, MAC_SEQNUM_LEN + len,
			    (char **) &hash);
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
	  *output = malloc (*output_len);
	  if (!*output)
	    return GSASL_MALLOC_ERROR;
	  memcpy (*output, input + MAC_DATA_LEN, len);
	}
      else
	return GSASL_INTEGRITY_ERROR;

      free (hash);
    }


  return GSASL_OK;
}
