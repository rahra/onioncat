#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#define FRAME_SIZE 2048

int main(int argc, char *argv[])
{
   char buf[FRAME_SIZE];
   char timestr[32];
   char *ptr = buf;
   int len, intro, i;
   time_t ts;
   struct tm *tm;

   read(0, buf, FRAME_SIZE);

   len = ntohs(*((uint16_t*) ptr));
   ptr += len + 2;
   ts = ntohl(*((uint32_t*) ptr));
   tm = localtime(&ts);
   strftime(timestr, 32, "%c", tm);
   ptr += 4;
   intro = ntohs(*((uint16_t*) ptr));
   ptr += 2;

   printf("key_len = %d\ntimestamp = \"%s\" (%ld)\nintro_point_cnt = %d\n", len, timestr, ts, intro);

   for (i = 0; i < intro; i++)
   {
      printf("intro_point[%d] = \"%s\"\n", i, ptr);
      ptr += strlen(ptr) + 1;
   }

   return 0;
}

