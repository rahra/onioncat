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

#ifndef OCATFDBUF_H
#define OCATFDBUF_H


#define FDBUF_SIZE 2048


typedef struct fdbuf
{
   int fd;                 //!< file descriptor
   int len;                //!< bytes within buffer
   int size;               //!< sizeof buffer
   char delim;             //!< delimiter
   char buf[FDBUF_SIZE];   //!< buffer
} fdbuf_t;


int fd_init(fdbuf_t *, int );
int fdgets(fdbuf_t *, char *, int );
int fdfill(fdbuf_t *);


#endif

