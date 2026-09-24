# crashgen

Hay un heap overflow sobre el top chunk. El último chunk de la lista creada por `split()` se encuentra adyacente al top chunk, si el campo de datos del último chunk es de 24 bytes este sobreescrive top_chunk.prev_size. Debido a un bug en `edit()` podemos llegar a sobreescribir también top_chunk.size. 

```C
void edit(Node *head)
{
  FILE *__stream;
  int idx;
  size_t word_len;
  int search__idx;
  Node *node;
  
  idx = get_idx();
  search__idx = 0;
  node = head;
  do {
    if (node == (Node *)0x0) {
LAB_00101643:
      puts("token edited");
      print_list(head);
      return;
    }
    if (idx == search__idx) {
      puts("edit how?");
      __stream = _stdin;
      // Here is the vulnerability
      word_len = strlen(node->word);
      fgets(node->word,(int)word_len,__stream);
      goto LAB_00101643;
    }
    node = (Node *)node->next;
    search__idx = search__idx + 1;
  } while( true );
}
```

Técnicas de explotación del heap en glibc 2.23 que usan el top chunk:
- House of Force: No es aplicable porque no podemos hacer malloc(N) para un N arbitrario)
- House of Orange: Útil la parte de usar sysmalloc_int_free para obtener un leak de libc.

Pasos para filtrar libc:
1. Con `edit` sobreescribimos el campo size del top chunk para que contenga un valor menor al espacio que podemos solicitar con `delete`. El nuevo tamaño que usamos, `0x671`, cumple ciertas condiciones necesarias:
    |                                                              |                                      |                  
    |--------------------------------------------------------------|--------------------------------------|
    | ((unsigned long) (old_size) >= MINSIZE                       | Debe ser al menos 0x20 bytes         |
    |  prev_inuse (old_top)                                        | Debe tener el byte PREV_INUSE activo |
    | ((unsigned long) old_end & (pagesize - 1)) == 0              | La direccion de top_chunk + size debe estar alineado a la pagina: (top_chunkaddr + size) & 0xfff == 0) |
2. Usamos `delete` para reservar un chunk grande. `delete` usa `get_idx` que a su vez usa `scanf` que reserva un chunk de 4096 (0x1000) bytes en el heap. Esto provoca que el top chunk se libere y vaya a `unsortedbin`.

`CrashReport` es una función que se invoca para manejar un SIGSEGV:
```C
void CrashReport(undefined8 param_1,long param_2,l ong param_3)
{
 // ...
   puts("what about fixing the program by your self?");
  iVar1 = getchar();
  getchar();
  if (((char)iVar1 != 'y') && ((char)iVar1 != 'Y')) {
    puts("giving up? what a shame...");
                    /* WARNING: Subroutine does not return * /
    exit(*(int *)(param_2 + 4));
  }
  puts("maybe stack is broken. let\'s clear and fix it");
  memset(pivot,0,0x1000);
  puts("where do you wan\'t to fix?");
  __isoc99_scanf(&DAT_00101aa9,&offset);
  getchar();
  puts("change memory for the fix?");
  __isoc99_scanf(&DAT_00101ac7,pivot + offset);
  getchar();
  puts("on second thought... it seems impossible");
                    /* WARNING: Subroutine does not return * /
  exit(-1);
}
```

Si tratamos de arreglar el stack podemos escribir 8 bytes en una dirección relativa al stack. A pesar de que el programa es PIE, es posible usa esto para sobreescribir parcialmente una dirección de retorno a crashgen.

Redirigiendo la ejecución al interior de `bug`, justo antes del `fgets`, podemos sobreescribir la dirección de retorno de una de las funciones internas de `fgets` y así ganar control del puntero a instrucción.

Lo restante es hacer ROP con gadgets de LIBC: (read-open-read-write o read-open-sendfile), dado que no se puede usar la syscall `execve` por el SECCOMP.

