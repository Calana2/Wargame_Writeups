# Sydney

```
448a <check_password>

448a:  bf90 3136 0000 cmp	#0x3631, 0x0(r15)

4490:  0d20           jnz	$+0x1c <check_password+0x22>

4492:  bf90 5164 0200 cmp	#0x6451, 0x2(r15)

4498:  0920           jnz	$+0x14 <check_password+0x22>

449a:  bf90 6128 0400 cmp	#0x2861, 0x4(r15)

44a0:  0520           jnz	$+0xc <check_password+0x22>

44a2:  1e43           mov	#0x1, r14

44a4:  bf90 6263 0600 cmp	#0x6362, 0x6(r15)

44aa:  0124           jz	$+0x4 <check_password+0x24>

44ac:  0e43           clr	r14

44ae:  0f4e           mov	r14, r15

44b0:  3041           ret
```

Ahora verifica la contraseña usando 2 bytes (words) a la vez. Si vemos el opcode de la instrucción actual notamos que esta arquitectura es little-endian:
```
CPU Cycles: 1479

bf90 3136 0000

cmp #0x3631, 0x0(r15)
```

Contraseña: `16Qda(bc`
