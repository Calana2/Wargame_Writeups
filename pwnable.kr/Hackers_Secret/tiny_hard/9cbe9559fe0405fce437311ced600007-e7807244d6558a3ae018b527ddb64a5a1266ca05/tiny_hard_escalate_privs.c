#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;

  getresuid(&ruid, &euid, &suid);
  getresgid(&rgid, &egid, &sgid);

  setresuid(suid, suid, suid);
  setresgid(sgid, sgid, sgid);

  printf("RUID, EUID, SUID: (%d, %d, %d)\n",ruid,euid,suid);
  printf("RGID, EGID, SGID: (%d, %d, %d)\n",rgid,egid,sgid);

  fflush(stdout);
  system("/bin/sh");
  return 0;
}