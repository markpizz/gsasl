/* Program name management.
   Copyright (C) 2001-2004 Free Software Foundation, Inc.
   Written by Bruno Haible <haible@clisp.cons.org>, 2001.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef PROGNAME_H
#define PROGNAME_H

/* Programs using this file should do the following in main():
     set_program_name (argv[0]);
 */


#ifdef __cplusplus
extern "C" {
#endif


/* String containing name the program is called with.  */
extern const char *program_name;

/* Set program_name, based on argv[0].  */
extern void set_program_name (const char *argv0);

/* Return short program name of the current executable, based on the
   earlier call to set_program_name.  Return NULL if unknown.  The
   short program name is computed by removing all directory names and
   path separators. */
extern const char *get_short_program_name (void);


#ifdef __cplusplus
}
#endif


#endif /* PROGNAME_H */
