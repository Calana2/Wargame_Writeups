# Tutorial

```
4484 <check_password>

4484:  6e4f           mov.b	@r15, r14

4486:  1f53           inc	r15

4488:  1c53           inc	r12

448a:  0e93           tst	r14

448c:  fb23           jnz	$-0x8 <check_password+0x0>

448e:  3c90 0900      cmp	#0x9, r12

4492:  0224           jz	$+0x6 <check_password+0x14>

4494:  0f43           clr	r15

4496:  3041           ret

4498:  1f43           mov	#0x1, r15

449a:  3041           ret
```

El dispositivo solo comprueba si la contraseña contiene 9 caracteres exactamente, incluyendo saltos de línea.

Posible contraseña: `12345678`
