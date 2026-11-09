# New-Orleans

El dispositivo genera una contraseña fija en la dirección 0x2400:
```
447e <create_password>

447e:  3f40 0024      mov	#0x2400, r15

4482:  ff40 5800 0000 mov.b	#0x58, 0x0(r15)

4488:  ff40 7800 0100 mov.b	#0x78, 0x1(r15)

448e:  ff40 5d00 0200 mov.b	#0x5d, 0x2(r15)

4494:  ff40 5700 0300 mov.b	#0x57, 0x3(r15)

449a:  ff40 4700 0400 mov.b	#0x47, 0x4(r15)

44a0:  ff40 3800 0500 mov.b	#0x38, 0x5(r15)

44a6:  ff40 3100 0600 mov.b	#0x31, 0x6(r15)

44ac:  cf43 0700      mov.b	#0x0, 0x7(r15)

44b0:  3041           ret
```

Y compara nuestra entrada contra ella:
```
44bc <check_password>

44bc:  0e43           clr	r14

44be:  0d4f           mov	r15, r13

44c0:  0d5e           add	r14, r13

44c2:  ee9d 0024      cmp.b	@r13, 0x2400(r14)

44c6:  0520           jnz	$+0xc <check_password+0x16>

44c8:  1e53           inc	r14

44ca:  3e92           cmp	#0x8, r14

44cc:  f823           jnz	$-0xe <check_password+0x2>

44ce:  1f43           mov	#0x1, r15

44d0:  3041           ret

44d2:  0f43           clr	r15
```

Inspeccionamos la memoria y vemos la contraseña correcta:
```
> read 2400
2400 5878 5d57 4738 3100 0000 0000 0000 0000  Xx]WG81.........
2410 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Contraseña: `Xx]WG81`

