/* printer.h --- Convert SCRAM token structures into strings.
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

#ifndef SCRAM_PRINTER_H
#define SCRAM_PRINTER_H

/* Get token types. */
#include "tokens.h"

extern int
scram_print_client_first (struct scram_client_first *cf, char **out);

extern int
scram_print_server_first (struct scram_server_first *cf, char **out);

extern int
scram_print_client_final (struct scram_client_final *cl, char **out);

extern int
scram_print_server_final (struct scram_server_final *sl, char **out);

#endif /* SCRAM_PRINTER_H */
