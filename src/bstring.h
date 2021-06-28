/* Copyright 2011 Bernhard R. Fischer, 2048R/5C5FFD47 <bf@abenteuerland.at>
 *
 * This file is part of libhpxml.
 *
 * Libhpxml is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * Libhpxml is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libhpxml. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef BSTRING_H
#define BSTRING_H


typedef struct bstrings
{
   short len;
   char *buf;
} bstrings_t;

typedef struct bstring
{
   int len;
   char *buf;
} bstring_t;

typedef struct bstringl
{
   long len;
   char *buf;
} bstringl_t;

int bs_advance(bstring_t *);
int bs_advancel(bstringl_t *);
int bs_advance2(bstring_t *);
int bs_nadvance(bstring_t *, int);
int bs_ncmp(bstring_t b, const char *s, int n);
int bs_cmp(bstring_t b, const char *s);
long bs_tol(bstring_t b);
double bs_tod(bstring_t b);
char *bs_strdup(const bstring_t *b);

#endif

