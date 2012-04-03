/* tokens.h --- Types for SCRAM tokens.
 * Copyright (C) 2009-2012 Simon Josefsson
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifndef SCRAM_TOKENS_H
#define SCRAM_TOKENS_H

/* Get size_t. */
#include <stddef.h>

struct scram_client_first
{
  char cbflag;
  char *cbname;
  char *authzid;
  char *username;
  char *client_nonce;
};

struct scram_server_first
{
  char *nonce;
  char *salt;
  size_t iter;
};

struct scram_client_final
{
  char *cbind;
  char *nonce;
  char *proof;
};

struct scram_server_final
{
  char *verifier;
};

extern void scram_free_client_first (struct scram_client_first *cf);

extern void scram_free_server_first (struct scram_server_first *sf);

extern void scram_free_client_final (struct scram_client_final *cl);

extern void scram_free_server_final (struct scram_server_final *sl);

#endif /* SCRAM_TOKENS_H */
