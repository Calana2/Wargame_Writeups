// libnosleep.c
// gcc -m32 -o libnosleep.so -shared -fpic libnosleep.c
#include <unistd.h>

// hook
unsigned int sleep(unsigned int seconds) { return 0; }
