/* shared.h --- DIGEST-MD5 mechanism from RFC 2831, shared definitions.
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

#ifndef SHARED_H
#define SHARED_H

#include "digest-md5.h"

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

#define COLON ":"
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

/* MIN(a,b) returns the minimum of A and B.  */
#ifndef MIN
# define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#define CLIENT_PRINT_OUTPUT 0
#define SERVER_PRINT_OUTPUT 0

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

extern const char *const digest_response_opts[];

#endif /* SHARED_H */
