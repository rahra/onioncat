/* Copyright 2011-2015 Bernhard R. Fischer, 2048R/5C5FFD47 <bf@abenteuerland.at>
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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "bstring.h"


/*! Advance bstring_t->buf and decrease bstring_t->len. This function does NOT
 * check if string length >= 1 and if b->buf != NULL which might result in
 * buffer underflows or segfaults.
 * @param b Pointer to bstring_t;
 * @return Length of string.
 */
int bs_advance(bstring_t *b)
{
   b->buf++;
   b->len--;
   return b->len;
}


int bs_advancel(bstringl_t *b)
{
   b->buf++;
   b->len--;
   return b->len;
}


/*! This function is like bs_advance() but does safety checks on pointers and
 * buffer length.
 * @param b Pointer to bstring_t.
 * @return Length of string.
 */
int bs_advance2(bstring_t *b)
{
   if (b == NULL || b->buf == NULL || b->len < 1)
      return 0;
   
   return bs_advance(b);
}


int bs_nadvance(bstring_t *b, int n)
{
   b->buf += n;
   b->len -= n;
   return b->len;
}


/*! bs_ncmp compares exactly n bytes of b and s. If they are equal, 0 is
 * returned. If they are not equal, the return value of strncmp(3) is returned.
 * If the string length of either is less then n, -2 is returned.
 */
int bs_ncmp(bstring_t b, const char *s, int n)
{
   if ((b.len < n) || ((int) strlen(s) < n))
      return -2;
   return strncmp(b.buf, s, n);
}


/*! This function compares a b_string to a regular C \0-terminated character
 * string.
 * @param b String as bstring_t structure.
 * @param s Pointer to C string.
 * @return The function returns an integer less than, equal, or greater than 0
 * exactly like strcmp(3).
 */
int bs_cmp(bstring_t b, const char *s)
{
   char c;

   // compare characters and return difference if they are not equal
   for (; b.len && *s; (void) bs_advance(&b), s++)
      if ((c = *b.buf - *s))
         return c;

   // strings are equal and of equal length
   if (!b.len && !*s)
      return 0;

   // string s is longer than b
   if (*s)
      return -*s;

   // string s is shorter than b
   return *b.buf;
}


/*! This function converts the string in b into a long integer. Currently, it
 * converts only decimal numbers, i.e. it uses a base of 10.
 * @param b String of type bstring_t.
 * @return The function returns the value of the converted string. The
 * conversion stops at the first character which is not between 0 and 9. Thus,
 * it returns 0 if there is no digit at the beginning of the string.
 * FIXME: This function should be improved to something similar to strtol(3).
 */
long bs_tol(bstring_t b)
{
   int n = 1;
   long l = 0;

   if (b.len && *b.buf == '-')
   {
      (void) bs_advance(&b);
      n = -1;
   }

   for (; b.len && *b.buf >= '0' && *b.buf <= '9'; (void) bs_advance(&b))
   {
      l *= 10;
      l += *b.buf - '0';
   }

   return l * n;
}


double bs_tod(bstring_t b)
{
   int n = 0, e;
   double d = 0.0;

   if (b.len && *b.buf == '-')
   {
      (void) bs_advance(&b);
      n = 1;
   }

   for (e = -1; b.len; (void) bs_advance(&b))
   {
      if (*b.buf == '.')
      {
         e++;
         continue;
      }
      if ((*b.buf < '0') || (*b.buf > '9'))
         break;
      if (e >= 0) e++;
      d *= 10.0;
      d += (double) (*b.buf - '0');
   }
   
   for (; e > 0; e--)
      d /= 10.0;

   if (n)
      return -d;

   return d;
}


/*! This function returns a \0-terminated string with the content of the
 * bstring_t b. The memory is malloc()'ed and must afterwards be freed again with
 * free() again.
 * @param b Pointer to bstring_t structure.
 * @return The function returns a pointer to \0-terminated string. 0 is
 * returned if b is a NULL pointer or malloc() failed. In the latter case,
 * errno is set according to malloc(3).
 */
char *bs_strdup(const bstring_t *b)
{
   char *s;

   if (b == NULL)
   {
      //errno = EFAULT;
      return NULL;
   }

   if ((s = malloc(b->len + 1)) == NULL)
      return NULL;

   if (b->buf != NULL)
      memcpy(s, b->buf, b->len);

   s[b->len] = '\0';

   return s;
}

