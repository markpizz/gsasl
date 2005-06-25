/* imap.h --- Header file for IMAP profile of SASL login.
 * Copyright (C) 2002, 2003, 2005  Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * GNU SASL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNU SASL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU SASL; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"

extern int imap_select_mechanism (char **mechlist);
extern int imap_authenticate (const char *mech);
extern int imap_step_send (const char *data);
extern int imap_step_recv (char **data);
extern int imap_auth_finish (void);
extern int imap_logout (void);
