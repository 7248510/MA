#include <stdio.h>
/* Compile flags as usual
cl /EHsc /sdl /W4 rule.c | ./rule.exe
./yara.exe -s -m rule.yara rule.exe 
*/
int main()
 {
   char connect[] = "Init winsock";
   char ipAddress[] = "10.0.1.7";
   char exact[] = "Exact match";
   printf("%s\n", ipAddress);
   printf("%s", connect);
 }
