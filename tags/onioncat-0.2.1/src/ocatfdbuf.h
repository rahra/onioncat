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

#ifndef OCATFDBUF_H
#define OCATFDBUF_H


#define FDBUF_SIZE 2048


typedef struct fdFile
{
   int fd;                 //!< file descriptor
   char buf[FDBUF_SIZE];   //!< buffer
   char *wp;               //!< write position
   char *rp;               //!< read position
   int len;                //!< readable bytes starting at read position
   char delim;             //!< delimiting character
   int eof;                //!< flag is set if EOF
} fdFile_t;


fdFile_t* fdf_init(int, char);
void fdf_free(fdFile_t *);
int fdf_read(fdFile_t *, char *, int);


#endif

