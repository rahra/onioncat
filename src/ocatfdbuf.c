/* Copyright 2008-2023 Bernhard R. Fischer.
 *
 * This file is part of OnionCat.
 *
 * OnionCat is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * OnionCat is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OnionCat. If not, see <http://www.gnu.org/licenses/>.
 */

/*! \file ocatfdbuf.c
 * This file contains functions which implements buffer IO based on file
 * descriptors similar to the f...-functions.
 * \author Bernhard R. Fischer <bf@abenteuerland.at>
 * \date 2023/01/23
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "ocat.h"
#include "ocatfdbuf.h"


int fd_init0(fdbuf_t *fdb, int fd, char delim)
{
   memset(fdb, 0, sizeof(*fdb));
   fdb->size = sizeof(fdb->buf);
   fdb->delim = delim;
   fdb->fd = fd;
   return 0;
}


int fd_init(fdbuf_t *fdb, int fd)
{
   return fd_init0(fdb, fd, '\n');
}


/*! This function copies len bytes out of fdb into the buffer buf but never
 * more than size bytes. If len is greater then the number of bytes available
 * in fdb, just the number of bytes available are copied. The data in the
 * destination buffer will be \0-terminated in any case.
 * The bytes copied are removed from fdb.
 * @param fdb Pointer to fdbuf_t structure.
 * @param buf Pointer to destinaton buffer.
 * @param size Size of destination buffer buf.
 * @param len Number of bytes to copy.
 * @return The function returns the number of bytes copied exluding the
 * terminating \0. If the buffer was too small, size is returned.
 */
int fdcopy(fdbuf_t *fdb, char *buf, int size, int len)
{
   int sb = 0;

   if (len > fdb->len)
      len = fdb->len;

   if (len >= size)
   {
      len = size - 1;
      sb = 1;
   }

   memcpy(buf, fdb->buf, len);
   buf[len] = '\0';

   memmove(fdb->buf, fdb->buf + len, fdb->len - len);
   fdb->len -= len;

   return len + sb;
}


/*! This function copies a string delimited by the delimiter of fdb (typically
 * \n) into the buffer buf. The string will be \0 delimited. The function will
 * copy size bytes at a maximium including the terminating \0.
 * @param fdb Pointer to fdbuf strucutre.
 * @param buf Pointer to data buffer to receive the string.
 * @param size Number of bytes available in buf.
 * @return The function returnes the number of bytes copied to buf excluding
 * the terminating \0, i.e. the return value usually is 0 <= len < size. If the
 * buffer is to small to receive the full data until the delimiter, size is
 * returned. The string will still be \0-terminated, thus size - 1 bytes have
 * been copied.
 * If the data in fdbuf contains no delimiting character the length of the
 * fdbuf data will be returned as a negative value.
 */
int fdgets(fdbuf_t *fdb, char *buf, int size)
{
   char *c;

   if ((c = memchr(fdb->buf, fdb->delim, fdb->len)) == NULL)
      return -fdb->len;

   return fdcopy(fdb, buf, size, c - fdb->buf + 1);
}


int fdfill(fdbuf_t *fdb)
{
   int len;

   // check if buffer space is available
   if (fdb->size - fdb->len <= 0)
   {
      errno = ENOBUFS;
      return -1;
   }

   // read data into buffer
   if ((len = read(fdb->fd, fdb->buf + fdb->len, fdb->size - fdb->len)) == -1)
      return -1;

   // check for EOF
   if (!len)
      return 0;

   log_debug("read %d bytes on %d", len, fdb->fd);

   // check for ^D of telnet
   if (len == 1 && fdb->buf[fdb->len] == 4)
      return 0;

   // increase data length value and return
   fdb->len += len;
   return len;
}

