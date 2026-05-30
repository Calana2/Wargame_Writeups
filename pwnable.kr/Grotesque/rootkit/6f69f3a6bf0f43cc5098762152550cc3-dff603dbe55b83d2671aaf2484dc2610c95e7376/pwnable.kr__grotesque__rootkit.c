#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>

unsigned long sys_open;  // 0xc1158d70
#define SYS_CALL_TABLE ((void **)0xc15fa020)
#define SYS_OPEN 5

MODULE_LICENSE("GPL");  // needed for kallsyms_lookup_name

int init_module(void) {
  printk(KERN_INFO "Hello\n");

  // get sys_open address
  sys_open = kallsyms_lookup_name("sys_open");
  printk(KERN_INFO "sys_open address: 0x%lx\n", sys_open);

  // overwrite syscall_table entry for sys_open hooked
  __asm__ (
   ".intel_syntax noprefix;"
   "mov eax, cr0;"
   "and eax, 0xfffeffff;"
   "mov cr0, eax;"
   ".att_syntax;"
  );

  SYS_CALL_TABLE[SYS_OPEN] = (void*)sys_open;
  
  // Not necesary, only for consistency
  __asm__ (
   ".intel_syntax noprefix;"
   "mov eax, cr0;"
   "or eax, 0x10000;"
   "mov cr0, eax;"
   ".att_syntax;"
  );

  printk(KERN_INFO "Job done\n");
  return 0;
}

void cleanup_module(void) { } 