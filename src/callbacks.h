/* callbacks.h --- Prototypes for SASL callbacks.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007  Simon Josefsson
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

#ifndef CALLBACKS_H
#define CALLBACKS_H

#include <gsasl.h>		/* Gsasl_session_ctx */

extern int callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop);

#endif /* CALLBACKS_H */
