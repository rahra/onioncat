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
 * This file contains functions which implements bufferd IO based on file
 * descriptors similar to the f...-functions. The advantage of this
 * implementation is that it is "officially" based on a filedescriptor which
 * makes it possible to select(2) on them. Use fd_fill() and fd_bufgets() for
 * that case.
 *
 * \author Bernhard R. Fischer <bf@abenteuerland.at>
 * \date 2023/01/31
 */

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "ocat.h"
#include "ocatfdbuf.h"


void fd_init0(fdbuf_t *fdb, int fd, char delim)
{
   memset(fdb, 0, sizeof(*fdb));
   fdb->size = sizeof(fdb->buf);
   fdb->delim = delim;
   fdb->fd = fd;
}


void fd_init(fdbuf_t *fdb, int fd)
{
   fd_init0(fdb, fd, '\n');
}


/*! This function opens the file pathname using open(2) and initializes fdb
 * appropriately.
 * @param fdb Pointer to fdbuf_t structure.
 * @param pathname Pathname of file to open.
 * @param flags Flags to be passed to open(2) (see there).
 * @return The function returns a valid filedescriptor. On error, -1 is
 * returned and errno is set appropriately.
 */
int fd_open(fdbuf_t *fdb, const char *pathname, int flags)
{
   int fd;

   if ((fd = open(pathname, flags)) == -1)
   {
      log_msg(LOG_ERR, "open(\"%s\") failed: %s", pathname, strerror(errno));
      return -1;
   }
   fd_init(fdb, fd);
   return fd;
}


/*! This function tests if the internal buffer of fdb is full.
 * @param Pointer to fdbuf_t structure-
 * @return Returns 1 if the buffer is full, otherwise 0 is returned.
 */
int fd_full(const fdbuf_t *fdb)
{
   return fdb->len >= fdb->size;
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
int fd_copy(fdbuf_t *fdb, char *buf, int size, int len)
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


/*! This function copies a string delimited by the delimiter (typically \n) out
 * of fdb into the buffer buf. The string will be \0 delimited. The function
 * will copy size bytes at a maximium including the terminating \0.
 * If the internal fdb buffer is completely full, buf will be filled even if
 * there are no delimiters in the data.
 * @param fdb Pointer to fdbuf strucutre.
 * @param buf Pointer to data buffer to receive the string.
 * @param size Number of bytes available in buf.
 * @return The function returnes the number of bytes copied to buf excluding
 * the terminating \0, i.e. the return value usually is 0 <= len < size, 0
 * meaning that no data was available in the buffer. If the
 * buffer is to small to receive the full data until the delimiter, size is
 * returned. The string will still be \0-terminated, thus size - 1 bytes have
 * been copied. If the data in fdbuf contains no delimiting character the
 * length of the fdbuf data will be returned as a negative value.
 */
int fd_bufgets(fdbuf_t *fdb, char *buf, int size)
{
   char *c;

   if ((c = memchr(fdb->buf, fdb->delim, fdb->len)) == NULL)
   {
      if (!fd_full(fdb))
         return -fdb->len;
      c = fdb->buf + fdb->size;
   }

   return fd_copy(fdb, buf, size, c - fdb->buf + 1);
}


/*! This function reads from date from the fildescriptor assciated with fdb
 * into the internal buffer. The function uses read(2) to read the data, i.e.
 * it will block depending if the filedescriptor is set to blocking or
 * non-blocking I/O. A call to select(2) may be used to determine if data is
 * available before calling fd_fill().
 * @param fdb Pointer to fdbuf_t structure.
 * @return The function returnes the number of bytes read from the
 * filedescriptor. In case of error, -1 is returned, an 0 in case if EOF (see
 * read(2) for further details).
 * Please note that a read of the single byte \004 will behave as if there was
 * EOF. This means the function will return 0 and the \004 byte will not be
 * written into the buffer (FIXME: Should this be handled outside of
 * fd_fill()?).
 */
int fd_fill(fdbuf_t *fdb)
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


/*! This function reads and returns a delimited string from the filedescriptor
 * defined in fdb. Actually this function is a combination of fd_fill() and
 * fd_bufgets().
 * The string returned in buf will always be \0-terminated.
 * This function bevhaves very similar to fgets(3).
 * @param fdb Pointer to fdbuf_t structure.
 * @param buf Pointer to destination buffer.
 * @param size Size of destination buffer.
 * @return This function will return the number of bytes returned in buf. If
 * EOF was reached, 0 is returned. In case of error, -1 is returned and errno
 * will be set appropriately.
 */
int fd_gets(fdbuf_t *fdb, char *buf, int size)
{
   fd_set rset;
   int len, maxfd;

   for (;;)
   {
      // get and handle data from buffer if available
      if ((len = fd_bufgets(fdb, buf, size)) > 0)
         return len;

      FD_ZERO(&rset);
      FD_SET(fdb->fd, &rset);

      // wait for data
      for (maxfd = 0; !maxfd;)
      {
         if ((maxfd = oc_select(fdb->fd + 1, &rset, NULL, NULL)) == -1)
         {
           // was interrupted?
           if (errno != EINTR)
              return -1;
           maxfd = 0;
         }
      }

      // read data into buffer
      len = fd_fill(fdb);
      //check EOF
      if (!len)
      {
         log_debug("EOF received on fd %d", fdb->fd);
         return 0;
      }
      // check error
      if (len == -1)
      {
         if (errno == ENOBUFS)
         {
            log_msg(LOG_WARNING, "buffer full, returning data without delimiter.");
            return fd_copy(fdb, buf, size, size);
         }
         log_msg(LOG_ERR, "read failed on %d: %s", fdb->fd, strerror(errno));
         return -1;
      }
   } // for (;;)
}

