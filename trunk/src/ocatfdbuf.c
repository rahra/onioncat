/* Copyright 2008-2009 Bernhard R. Fischer.
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


#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "ocatfdbuf.h"


/*! Init fdFile_t structure.
 *  The function allocates memory, hence,
 *  it must be freed again with fdf_free().
 *  @param fd File descriptor if open file.
 *  @param delim Delimiting character.
 *  @return Pointer to fdFile_t structure or NULL in case of error.
 *          In the latter case errno is set appropriately.
 **/
fdFile_t* fdf_init(int fd, char delim)
{
   fdFile_t *fdf;
   long flags;

   // set fd in non-blocking mode
   if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
      return NULL;
   if ((fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1)
      return NULL;

   if (!(fdf = malloc(sizeof(fdFile_t))))
      return NULL;

   fdf->fd = fd;
   fdf->wp = fdf->rp = fdf->buf;
   fdf->len = 0;
   fdf->delim = delim;
   fdf->eof = 0;

   return fdf;
}


void fdf_free(fdFile_t *fdf)
{
   free(fdf);
}


/*! Block and read data into buffer as soon as it is available.
 *  @param fdf Pointer to fdFile_t structure.
 *  @return Number of bytes read or -1 if an error occured. In the
 *          latter case errno is set appropriately. If the number of
 *          bytes is 0, then the buffer is full.
 */
int fdf_fill(fdFile_t *fdf)
{
   fd_set rset;
   int maxfd = -1, len;

   // cycle write position
   if (fdf->wp >= fdf->buf + FDBUF_SIZE)
      fdf->wp = fdf->buf;

   FD_ZERO(&rset);
   FD_SET(fdf->fd, &rset);

   if ((maxfd = select(fdf->fd + 1, &rset, NULL, NULL, NULL)) == -1)
      return -1;

   if (maxfd != 1)
      // Fatal error. This should never happen.
      exit(1);

   // test if write position is behind read position
   if (fdf->wp > fdf->rp)
      len = FDBUF_SIZE - (fdf->wp - fdf->buf);
   // test if write position is before read position
   else if (fdf->wp < fdf->rp)
      len = fdf->rp - fdf->wp;
   // if equal, test if buffer is full
   else if (fdf->len)
      return 0;
   // else the buffer is empty, read to the end
   else
      len = FDBUF_SIZE - (fdf->wp - fdf->buf);

   // read bytes into buffer
   if ((len = read(fdf->fd, fdf->wp, len)) == -1)
      return -1;

   // test and set end-of-file
   if (!len)
      fdf->eof++;

   // advance write position
   fdf->wp += len;
   // increase number of readable bytes
   fdf->len += len;

   return len;
}


/*! Copy bytes sequentially out of buffer. fdf_memcpy() does
 *  correctly move the read position pointer and decreases
 *  the byte counter.
 *  @param fdf Pointer to fdFile_t structure.
 *  @param buf Pointer to destination memory.
 *  @param n Number of bytes to copy. fdf_memcpy() does not check
 *           memory boundaries, hence, n must not be larger than 
 *           fdf->rp - FDBUF_SIZE and buf must be large enough to
 *           receive all bytes.
 *  @return Number of bytes copied. This should always be n.
 */
int fdf_memcpy(fdFile_t *fdf, char *buf, int n)
{
   memcpy(buf, fdf->rp, n);
   fdf->rp += n;
   fdf->len -= n;
   // set read position pointer to the beginning if it reached the end
   if (fdf->rp >= fdf->buf + FDBUF_SIZE)
      fdf->rp = fdf->buf;
   return n;
}


/*! This is similar to fdf_memcpy but it copies memory which is 
 *  wrapped around and it honors memory boundaries given by n and s.
 *  @param fdf Pointer to fdFile_t structure.
 *  @param buf Pointer to destination memory.
 *  @param n Number of bytes available in buf.
 *  @param s Number of bytes to copy.
 *  @return Number of bytes copied.
 */
int fdf_wrpcpy(fdFile_t *fdf, char *buf, int n, int s)
{
   int len = fdf->buf + FDBUF_SIZE - fdf->rp;

   // check if bytes to copy do wrap
   if (s < len)
      len = s;
   // copy part starting at the read position
   if (n < len)
      return fdf_memcpy(fdf, buf, n);
   fdf_memcpy(fdf, buf, len);
   // copy part at the beginning
   buf += len;
   if (n < s)
      return fdf_memcpy(fdf, buf, n - len) + len;
   return fdf_memcpy(fdf, buf, s - len) + len;
}

 
/*! Read n of bytes from file identified by fdf into buf.
 *  The bytes are copied to buf including the delimiter character
 *  except buf is too small. In that case it is filled to the
 *  maximum and of course does not include the delimiter.
 *  @param fdf Pointer to fdFile_t structure.
 *  @param buf Pointer to destination memory.
 *  @param n Number of bytes available in buf.
 *  @return Nuber of bytes actually read or -1 on error.
 */
int fdf_read(fdFile_t *fdf, char *buf, int n)
{
   int len;
   char *s = NULL;

   for (;;)
   { 
      // determine if read buffer is wrapped
      if (fdf->rp + fdf->len <= fdf->buf + FDBUF_SIZE)
         // no
         len = fdf->len;
      else
         // yes
         len = (fdf->buf + FDBUF_SIZE) - fdf->rp;

      // search delimiter in unwrapped part behind read position
      if ((s = memchr(fdf->rp, fdf->delim, len)))
         return fdf_wrpcpy(fdf, buf, n, s - fdf->rp + 1);

      // test if wrapped part at the beginning of the buffer exists
      if ((fdf->len - len))
         // test if delimiter is found in the wrapped part at the beginning of the buffer
         if ((s = memchr(fdf->buf, fdf->delim, fdf->len - len)))
            return fdf_wrpcpy(fdf, buf, n, s - fdf->buf + len);

      // test if buffer is full
      if (fdf->len >= FDBUF_SIZE)
         return fdf_wrpcpy(fdf, buf, n, FDBUF_SIZE);

      if (fdf->eof)
         return 0;

      if ((len = fdf_fill(fdf)) == -1)
         return -1;
   }
}

