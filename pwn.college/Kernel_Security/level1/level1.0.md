# level1.0

Me descargo el módulo para analizarlo con Ghidra en mi PC:
```
 sftp -i ~/.ssh/pwn_college_key hacker@dojo.pwn.college
Connected to dojo.pwn.college.
sftp> ls
Desktop         project.gpr     project.lock    project.lock~   project.rep
sftp> cd /challenge
sftp> ls
babykernel_level1.0.ko
sftp> get babykernel_level1.0.ko
Fetching /challenge/babykernel_level1.0.ko to babykernel_level1.0.ko
babykernel_level1.0.ko                                                                                             100%  274KB  91.5KB/s   00:03
sftp>
```

```
hacker@kernel-security~level1-0:~$ vm start
hacker@kernel-security~level1-0:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
Last login: Fri Aug  7 19:52:25 2026 from 10.0.2.2
hacker@vm_kernel-security~level1-0:~$ cd /challenge
hacker@vm_kernel-security~level1-0:/challenge$ nm babykernel_level1.0.ko 
000000000000002e r __UNIQUE_ID_author33
0000000000000070 r __UNIQUE_ID_depends23
000000000000000c r __UNIQUE_ID_description34
0000000000000041 r __UNIQUE_ID_license32
0000000000000085 r __UNIQUE_ID_name21
0000000000000079 r __UNIQUE_ID_retpoline22
000000000000004d r __UNIQUE_ID_srcversion24
0000000000000094 r __UNIQUE_ID_vermagic20
0000000000000000 r __UNIQUE_ID_version35
                 U __stack_chk_fail
0000000000000000 D __this_module
                 U _copy_from_user
                 U _copy_to_user
0000000000000000 r _note_6
0000000000000000 t bin_padding
0000000000000d50 T cleanup_module
0000000000000015 t device_open
00000000000000b8 t device_read
0000000000000000 t device_release
0000000000000008 b device_state
000000000000002a t device_write
                 U filp_close
                 U filp_open
0000000000000020 b flag
0000000000000000 d fops
0000000000000c80 T init_module
                 U kernel_read
                 U printk
                 U proc_create
0000000000000000 B proc_entry
                 U proc_remove
                 U strncmp
```

Se puede observar que crea una entrada proc, en el log de la inicialización del sistema vemos la información del reto:
```
hacker@vm_kernel-security~level1-0:/challenge$ dmesg |tail
[    4.104185] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready
[    4.170754] challenge: loading out-of-tree module taints kernel.
[    4.174354] ###
[    4.175059] ### Welcome to this kernel challenge!
[    4.176928] ###
[    4.177664] This challenge will misuse the kernel in a way that will teach you about basic kernel exploitation.
[    4.181422] This challenge exposes a simple character device interface through `/proc/pwncollege`.
[    4.184783] You can open, read, write, close this device as you would any other file.
[    4.187838] If you can figure out the password, the character device will allow you to read the flag.
[    4.191430] Good luck!
```

Debemos interactuar con `/proc/pwncollege`, pasarle una contraseña y este nos dará la flag supuestamente:
```
hacker@vm_kernel-security~level1-0:/challenge$ cat /proc/pwncollege|head
password:
password:
password:
password:
password:
password:
password:
password:
password:
password:
```

`device_write` es la rutina invocada cuando se escribe al dispositivo. Se aprecia una comparación y una actualización del estado del dispositivo:
```C
ssize_t device_write(file *file,char *buffer,size_t lengt h,loff_t *offset)
{
  long lVar1;
  int iVar2;
  size_t sVar3;
  long in_GS_OFFSET;
  char password [16];
  
  lVar1 = *(long *)(in_GS_OFFSET + 0x28);
  printk(&DAT_00100f40,file,buffer,length,offset);
  sVar3 = 0x10;
  if (length < 0x11) {
    sVar3 = length;
  }
  _copy_from_user(password,buffer,sVar3);
  iVar2 = strncmp(password,"jhybaaflbcfnawgz",0x10);
  device_state = (iVar2 == 0) + '\x01';
  if (lVar1 != *(long *)(in_GS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return * /
    __stack_chk_fail();
  }
  return length;
}
```

Si `device_state` es actualizado a '2' de esta forma entonces el programa devuelve la flag en las siguientes lecturas:
```C

/* WARNING: Unknown calling convention */

ssize_t device_read(file *file,char *buffer,size_t length ,loff_t *offset)

{
  char cVar1;
  long lVar2;
  ulong uVar3;
  char *pcVar4;
  char *pcVar5;
  byte bVar6;
  
  bVar6 = 0;
  printk(&DAT_00100f80,file,buffer,length,offset);
  pcVar4 = flag;
  if ((((device_state != '\x02') &&
       (pcVar4 = "device error: unknown state\n", device_ state < '\x03')) &&
      (pcVar4 = "password:\n", device_state != '\0')) &&
     (pcVar4 = "device error: unknown state\n", device_s tate == '\x01')) {
    device_state = '\0';
    pcVar4 = "invalid password\n";
  }
  uVar3 = 0xffffffffffffffff;
  pcVar5 = pcVar4;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + (ulong)bVar6 * -2 + 1;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3 - 1;
  if (uVar3 <= length) {
    length = uVar3;
  }
  lVar2 = _copy_to_user(buffer,pcVar4,length);
  return uVar3 - lVar2;
}
```

Puedes ver la contraseña volcando las cadenas del programa de todas formas:
```
hacker@vm_kernel-security~level1-0:/challenge$ strings babykernel_level1.0.ko |head -n 20
Linux
[]A\
6[device_release] inode=%px, file=%px
6[device_open] inode=%px, file=%px
6[device_write] file=%px, buffer=%px, length=%lu, offset=%px
6[device_read] file=%px, buffer=%px, length=%lu, offset=%px
6### Welcome to this kernel challenge!
6This challenge will misuse the kernel in a way that will teach you about basic kernel exploitation.
6This challenge exposes a simple character device interface through `/proc/pwncollege`.
6You can open, read, write, close this device as you would any other file.
6If you can figure out the password, the character device will allow you to read the flag.
jhybaaflbcfnawgz
invalid password
password:
device error: unknown state
/flag
pwncollege
6###
6Good luck!
version=1.0
hacker@vm_kernel-security~level1-0:/challenge$ echo -n "`strings babykernel_level1.0.ko | sed -n 12p`"  > /proc/pwncollege  | head -1 /proc/pwncollege
pwn.college{0TX6TaYB8QrmWoeBiU29_A51Zen.dNjM0wCNwYzM5EzW}
```

`pwn.college{0TX6TaYB8QrmWoeBiU29_A51Zen.dNjM0wCNwYzM5EzW}`
