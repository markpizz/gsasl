/* utils.h --- Prototypes for self test utilities.
 * Copyright (C) 2002, 2003, 2004, 2005, 2007, 2008  Simon Josefsson
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

#ifndef UTILS_H
# define UTILS_H

# include <string.h>
# include <stdarg.h>
# include <gsasl.h>

extern int debug;
extern int error_count;
extern int break_on_error;

extern void fail (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));
extern void success (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));
extern void escapeprint (const char *str, size_t len);
extern void hexprint (const char *str, size_t len);
extern void binprint (const char *str, size_t len);

/* This must be implemented elsewhere. */
extern void doit (void);

#endif /* UTILS_H */
