/* imap.h --- Header file for IMAP profile of SASL login.
 * Copyright (C) 2002-2012 Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "internal.h"

extern int imap_greeting (void);
extern int imap_has_starttls (void);
extern int imap_starttls (void);
extern int imap_select_mechanism (char **mechlist);
extern int imap_authenticate (const char *mech);
extern int imap_step_send (const char *data);
extern int imap_step_recv (char **data);
extern int imap_auth_finish (void);
extern int imap_logout (void);
