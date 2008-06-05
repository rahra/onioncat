#include "config.h"

#include <stdio.h>
#include <sys/types.h>


#ifndef HAVE_STRLCAT

size_t strlcat(char *dst, const char *src, size_t size)
{
  int i;
   for (i = 0; *dst && i < size; i++, dst++);
   if (i >= size)
      return size;
   for ( ; *src && i < size; i++, dst++, src++)
      *dst = *src;
   if (i >= size)
      dst--, i--;
   *dst = '\0';
   return i;
}

#endif


#if 0

int main(int argc, char *argv[])
{
   int i;
   char buf[20] = "abcdefg";

   if (argc == 1)
      return 1;
   i = strlcat(buf, argv[1], 20);
   printf("%d \"%s\"\n", i, buf);

   return 0;
}

#endif

