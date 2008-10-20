/* ioctl.c --- wrappers for Windows socket ioctl function

   Copyright (C) 2008 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Paolo Bonzini */

#include <config.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#define FD_TO_SOCKET(fd)   ((SOCKET) _get_osfhandle ((fd)))

static inline void
set_winsock_errno (void)
{
  int err = WSAGetLastError ();
  WSASetLastError (0);

  /* Map some WSAE* errors to the runtime library's error codes.  */
  switch (err)
    {
    case WSA_INVALID_HANDLE:
      errno = EBADF;
      break;
    case WSA_NOT_ENOUGH_MEMORY:
      errno = ENOMEM;
      break;
    case WSA_INVALID_PARAMETER:
      errno = EINVAL;
      break;
    case WSAEWOULDBLOCK:
      errno = EWOULDBLOCK;
      break;
    case WSAENAMETOOLONG:
      errno = ENAMETOOLONG;
      break;
    case WSAENOTEMPTY:
      errno = ENOTEMPTY;
      break;
    default:
      errno = (err > 10000 && err < 10025) ? err - 10000 : err;
      break;
    }
}

int
rpl_ioctl (int fd, int req, ...)
{
  void *buf;
  va_list args;
  SOCKET sock;
  int r;

  va_start (args, req);
  buf = va_arg (args, void *);
  va_end (args);

  sock = FD_TO_SOCKET (fd);
  r = ioctlsocket (sock, req, buf);
  if (r < 0)
    set_winsock_errno ();

  return r;
}
