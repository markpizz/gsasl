/* md5pwd.c	find passwords in UoW imapd MD5 type password files 
 * Copyright (C) 2002  Simon Josefsson
 *
 * This file is part of libgsasl.
 *
 * Libgsasl is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Libgsasl is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with libgsasl; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

/**
 * gsasl_md5pwd_get_password:
 * @filename: filename of file containing passwords.
 * @username: username string.
 * @key: output character array.
 * @keylen: input maximum size of output character array, on output
 * contains actual length of output array.
 * 
 * Retrieve password for user from specified file.  To find out how
 * large the output array must be, call this function with out=NULL.
 * 
 * The file should be on the UoW "MD5 Based Authentication" format,
 * which means it is in text format with comments denoted by # first
 * on the line, with user entries looking as username\tpassword.  This
 * function removes \r and \n at the end of lines before processing.
 *
 * Return value: Return GSASL_OK if output buffer contains the
 * password, GSASL_AUTHENTICATION_ERROR if the user could not be
 * found, or other error code.
 **/
int
gsasl_md5pwd_get_password (const char *filename, 
			   const char *username,
			   char *key,
			   size_t *keylen)
{
  char matchbuf[BUFSIZ];
  char line[BUFSIZ];
  FILE *fh;

  fh = fopen(filename, "r");
  if (fh == NULL)
      return GSASL_FOPEN_ERROR;

  sprintf(matchbuf, "%s\t", username);

  while (!feof(fh))
    {
      if (fgets(line, BUFSIZ, fh) == NULL)
	break;

      if (line[0] == '#')
	continue;

      while (strlen(line) > 0 && (line[strlen(line)-1] == '\n' || 
				  line[strlen(line)-1] == '\r'))
	line[strlen(line)-1] = '\0';

      if (strlen(line) <= strlen(matchbuf))
	continue;

      if (strncmp(matchbuf, line, strlen(matchbuf)) == 0)
	{
	  if (*keylen < strlen(line) - strlen(matchbuf))
	    {
	      fclose(fh);
	      return GSASL_TOO_SMALL_BUFFER;
	    }

	  *keylen = strlen(line) - strlen(matchbuf);

	  if (key)
	    memcpy(key, &line[strlen(matchbuf)], *keylen);

	  fclose(fh);

	  return GSASL_OK;
	}
    }
  
  if (fclose(fh) != 0)
    return GSASL_FCLOSE_ERROR;

  return GSASL_AUTHENTICATION_ERROR;
}
