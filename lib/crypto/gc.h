/* gc.h --- Header file for implementation agnostic crypto wrapper API.
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
 * License along with GC; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#ifndef GC_H
#define GC_H

/* Get size_t. */
#include <stddef.h>

/* Get uint8_t. */
#include <nettle-types.h> /* XXX */

typedef enum gc_rc {
  GC_OK = 0,
  GC_INIT_ERROR,
  GC_RANDOM_ERROR,
  GC_MD5_ERROR
} Gc_rc;

#define GC_MD5_LEN 16

extern int gc_init (void);
extern void gc_done (void);

extern int gc_nonce (uint8_t *data, size_t datalen);
extern int gc_random (uint8_t *data, size_t datalen);

extern int gc_md5 (const uint8_t *in, size_t inlen, uint8_t out[GC_MD5_LEN]);

extern int gc_hmac_md5 (const uint8_t *key, size_t keylen,
			const uint8_t *in, size_t inlen,
			uint8_t outhash[GC_MD5_LEN]);

#endif /* GC_H */
