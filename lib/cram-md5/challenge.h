/* challenge.h --- Generate a CRAM-MD5 challenge string.
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

#ifndef CHALLENGE_H
# define CHALLENGE_H

# define CRAM_MD5_CHALLENGE_LEN 32

/* Store CRAM-MD5 challenge in output buffer. */
extern void cram_md5_challenge (char challenge[CRAM_MD5_CHALLENGE_LEN]);

#endif /* CHALLENGE_H */
