/* session.h --- Data integrity/privacy protection of DIGEST-MD5.
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

#ifndef SESSION_H
#define SESSION_H

#include "digest-md5.h"

int
digest_md5_encode (Gsasl_session * sctx,
		   const char *input, size_t input_len,
		   char **output, size_t * output_len,
		   Gsasl_qop qop,
		   uint32_t sendseqnum,
		   char key[MD5LEN]);

int
digest_md5_decode (Gsasl_session * sctx,
		   const char *input,
		   size_t input_len,
		   char **output, size_t * output_len,
		   Gsasl_qop qop,
		   uint32_t readseqnum,
		   char key[MD5LEN]);

#endif /* SESSION_H */
