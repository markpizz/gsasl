/* gc.h --- Header file for implementation agnostic crypto wrapper API.
 * Copyright (C) 2002, 2003, 2004, 2005  Simon Josefsson
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1, or (at your
 * option) any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#ifndef GC_H
# define GC_H

/* Get size_t. */
# include <stddef.h>

#define GC_MD5_DIGEST_SIZE 16

enum Gc_rc
  {
    GC_OK = 0,
    GC_MALLOC_ERROR,
    GC_INIT_ERROR,
    GC_RANDOM_ERROR,
    GC_INVALID_CIPHER,
    GC_INVALID_HASH,
    GC_PKCS5_INVALID_ITERATION_COUNT,
    GC_PKCS5_INVALID_DERIVED_KEY_LENGTH,
    GC_PKCS5_DERIVED_KEY_TOO_LONG
  };
typedef enum Gc_rc Gc_rc;

extern int gc_init (void);
extern void gc_done (void);

/* Memory allocation (avoid). */
typedef void *(*gc_malloc_t) (size_t n);
typedef int (*gc_secure_check_t) (const void *);
typedef void *(*gc_realloc_t) (void *p, size_t n);
typedef void (*gc_free_t) (void *);
extern void gc_set_allocators (gc_malloc_t func_malloc,
			       gc_malloc_t secure_malloc,
			       gc_secure_check_t secure_check,
			       gc_realloc_t func_realloc,
			       gc_free_t func_free);

/* One-call interface. */
extern int gc_md5 (const void *in, size_t inlen, void *resbuf);
extern int gc_hmac_md5 (const void *key, size_t keylen,
			const void *in, size_t inlen,
			char *resbuf);

#endif /* GC_H */
