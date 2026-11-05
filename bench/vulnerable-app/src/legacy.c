#include <stdio.h>

/* Liest einen Namen von der Konsole und gibt ihn aus */
void greet(void) {
  char name[16];
  gets(name);
  printf(name);
}
